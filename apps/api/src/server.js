// torvex api - e2e encrypted relay with device routing
// hardened auth, ws protection, zero-knowledge message relay

import "dotenv/config";
import { createServer } from "node:http";
import { randomBytes } from "node:crypto";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import { WebSocketServer } from "ws";
import { v4 as uid } from "uuid";
import nacl from "tweetnacl";
import bs58 from "bs58";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import { eq, and, sql } from "drizzle-orm";
import { db } from "./db/index.js";
import { users, messages, oneTimePrekeys } from "./db/schema.js";

const PORT = process.env.PORT || 4400;
const JWT_SECRET = process.env.JWT_SECRET;
const ALLOWED_ORIGINS =
  process.env.ALLOWED_ORIGINS?.split(",").map((s) => s.trim()) || [];
const IS_PROD = process.env.NODE_ENV === "production";

if (!JWT_SECRET || JWT_SECRET.length < 64)
  throw new Error("JWT_SECRET must be at least 64 chars");

const CHALLENGE_TTL = 30_000;
const CHALLENGE_MAX = 10_000;
const TOKEN_EXPIRY = "24h";
const WS_MAX_MSG = 32_768;
const WS_MSG_RATE = { window: 1000, max: 10 };
const WS_MAX_CONNECTIONS_PER_IP = 5;
const ENCPUB_PATTERN = /^[1-9A-HJ-NP-Za-km-z]{32,64}$/;
const PUBKEY_MIN = 10;
const PUBKEY_MAX = 128;

const app = express();
app.set("trust proxy", IS_PROD ? 1 : false);
app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        connectSrc: ["'self'", "wss:", "ws:"],
      },
    },
    hsts: IS_PROD
      ? { maxAge: 31536000, includeSubDomains: true, preload: true }
      : false,
    referrerPolicy: { policy: "no-referrer" },
    crossOriginEmbedderPolicy: false,
  }),
);

app.use(
  cors({
    origin: ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS : "*",
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
    maxAge: 86400,
  }),
);

app.use(express.json({ limit: "8kb" }));

app.use((req, res, next) => {
  req.id = randomBytes(8).toString("hex");
  res.setHeader("X-Request-ID", req.id);
  next();
});

const authLimiter = rateLimit({
  windowMs: 60_000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "rate limited" },
});

app.use("/auth", authLimiter);

const challenges = new Map();
const sockets = new Map();
const encPubs = new Map();
const wsPerIp = new Map();
const revokedTokens = new Set();

function verifyToken(raw) {
  if (!raw || typeof raw !== "string" || raw.length > 2048) return null;
  try {
    const payload = jwt.verify(raw, JWT_SECRET, { algorithms: ["HS256"] });
    if (revokedTokens.has(payload.jti)) return null;
    if (!payload.sub || typeof payload.sub !== "string") return null;
    return payload;
  } catch {
    return null;
  }
}

function isValidPubkey(pk) {
  return (
    typeof pk === "string" &&
    pk.length >= PUBKEY_MIN &&
    pk.length <= PUBKEY_MAX &&
    /^[a-zA-Z0-9]+$/.test(pk)
  );
}

function clientIp(req) {
  return req.ip || req.socket?.remoteAddress || "unknown";
}

app.post("/auth/challenge", (req, res) => {
  const { pubkey } = req.body;

  if (!pubkey || !isValidPubkey(pubkey))
    return res.status(400).json({ error: "invalid pubkey" });

  if (challenges.size >= CHALLENGE_MAX) {
    const now = Date.now();
    for (const [k, v] of challenges) {
      if (now - v.created > CHALLENGE_TTL) challenges.delete(k);
    }
    if (challenges.size >= CHALLENGE_MAX)
      return res.status(503).json({ error: "server busy" });
  }

  const nonce = randomBytes(32).toString("hex");
  const challenge = `torvex-auth:${nonce}:${Date.now()}`;
  challenges.set(pubkey, { challenge, created: Date.now(), ip: clientIp(req) });
  setTimeout(() => challenges.delete(pubkey), CHALLENGE_TTL);
  res.json({ challenge });
});

app.post("/auth/verify", async (req, res) => {
  const { pubkey, signature, deviceId } = req.body;

  if (
    !pubkey ||
    !signature ||
    typeof signature !== "string" ||
    signature.length > 1024
  )
    return res.status(400).json({ error: "invalid request" });

  const entry = challenges.get(pubkey);
  if (!entry) return res.status(401).json({ error: "no challenge" });
  if (Date.now() - entry.created > CHALLENGE_TTL)
    return res.status(401).json({ error: "expired" });

  challenges.delete(pubkey);

  try {
    const sigBytes = bs58.decode(signature);
    const pubBytes = bs58.decode(pubkey);
    if (pubBytes.length !== 32)
      return res.status(400).json({ error: "invalid pubkey length" });
    if (sigBytes.length !== 64)
      return res.status(400).json({ error: "invalid signature length" });
    if (
      !nacl.sign.detached.verify(
        new TextEncoder().encode(entry.challenge),
        sigBytes,
        pubBytes,
      )
    )
      return res.status(401).json({ error: "bad signature" });

    const did = typeof deviceId === "string" && deviceId.length <= 64 ? deviceId : null;
    const jti = randomBytes(16).toString("hex");
    const token = jwt.sign(
      { sub: pubkey, jti, did, iat: Math.floor(Date.now() / 1000) },
      JWT_SECRET,
      {
        algorithm: "HS256",
        expiresIn: TOKEN_EXPIRY,
      },
    );

    try {
      await db.insert(users).values({ pubkey }).onConflictDoNothing();
    } catch (e) {
      console.error(`[${req.id}] db user insert:`, e.message);
    }

    res.json({ token, pubkey, deviceId: did });
  } catch (e) {
    console.error(`[${req.id}] verify error:`, e.message);
    res.status(400).json({ error: "verification failed" });
  }
});

app.get("/auth/me", (req, res) => {
  const payload = verifyToken(
    req.headers.authorization?.replace("Bearer ", ""),
  );
  if (!payload) return res.status(401).json({ error: "unauthorized" });
  res.json({ pubkey: payload.sub });
});

app.post("/auth/revoke", (req, res) => {
  const payload = verifyToken(
    req.headers.authorization?.replace("Bearer ", ""),
  );
  if (!payload) return res.status(401).json({ error: "unauthorized" });
  revokedTokens.add(payload.jti);
  setTimeout(() => revokedTokens.delete(payload.jti), 24 * 60 * 60 * 1000);
  res.json({ ok: true });
});

function authMiddleware(req, res, next) {
  const payload = verifyToken(
    req.headers.authorization?.replace("Bearer ", ""),
  );
  if (!payload) return res.status(401).json({ error: "unauthorized" });
  req.pubkey = payload.sub;
  next();
}

app.post("/keys/bundle", authMiddleware, async (req, res) => {
  const {
    identityKey,
    signedPrekey,
    signedPrekeySig,
    oneTimePrekeys: otps,
  } = req.body;

  if (!identityKey || !signedPrekey || !signedPrekeySig)
    return res.status(400).json({ error: "missing prekey fields" });
  if (
    typeof identityKey !== "string" ||
    typeof signedPrekey !== "string" ||
    typeof signedPrekeySig !== "string"
  )
    return res.status(400).json({ error: "invalid prekey types" });
  if (
    identityKey.length > 128 ||
    signedPrekey.length > 128 ||
    signedPrekeySig.length > 256
  )
    return res.status(400).json({ error: "prekey too large" });

  try {
    await db
      .update(users)
      .set({ identityKey, signedPrekey, signedPrekeySig })
      .where(eq(users.pubkey, req.pubkey));

    if (Array.isArray(otps) && otps.length > 0 && otps.length <= 100) {
      const rows = otps
        .filter(
          (k) =>
            typeof k.id === "number" &&
            typeof k.publicKey === "string" &&
            k.publicKey.length <= 128,
        )
        .map((k) => ({
          id: `${req.pubkey}:${k.id}`,
          pubkey: req.pubkey,
          prekeyIndex: k.id,
          publicKey: k.publicKey,
          used: false,
        }));
      if (rows.length)
        await db.insert(oneTimePrekeys).values(rows).onConflictDoNothing();
    }

    res.json({ ok: true });
  } catch (e) {
    console.error(`[${req.id}] bundle upload:`, e.message);
    res.status(500).json({ error: "bundle upload failed" });
  }
});

app.get("/keys/bundle/:pubkey", authMiddleware, async (req, res) => {
  const target = req.params.pubkey;
  if (!isValidPubkey(target))
    return res.status(400).json({ error: "invalid pubkey" });

  try {
    const [user] = await db
      .select({
        identityKey: users.identityKey,
        signedPrekey: users.signedPrekey,
        signedPrekeySig: users.signedPrekeySig,
      })
      .from(users)
      .where(eq(users.pubkey, target))
      .limit(1);

    if (!user?.identityKey) return res.status(404).json({ error: "no bundle" });

    const [otp] = await db
      .select({
        id: oneTimePrekeys.id,
        prekeyIndex: oneTimePrekeys.prekeyIndex,
        publicKey: oneTimePrekeys.publicKey,
      })
      .from(oneTimePrekeys)
      .where(
        and(eq(oneTimePrekeys.pubkey, target), eq(oneTimePrekeys.used, false)),
      )
      .limit(1);

    if (otp)
      await db
        .update(oneTimePrekeys)
        .set({ used: true })
        .where(eq(oneTimePrekeys.id, otp.id));

    res.json({
      identityKey: user.identityKey,
      signedPrekey: user.signedPrekey,
      signedPrekeySig: user.signedPrekeySig,
      oneTimePrekey: otp
        ? { id: otp.prekeyIndex, publicKey: otp.publicKey }
        : null,
    });
  } catch (e) {
    console.error(`[${req.id}] bundle fetch:`, e.message);
    res.status(500).json({ error: "bundle fetch failed" });
  }
});

app.post("/profile/name", authMiddleware, async (req, res) => {
  const { displayName } = req.body;
  if (
    !displayName ||
    typeof displayName !== "string" ||
    displayName.length > 32
  )
    return res.status(400).json({ error: "invalid name (max 32 chars)" });
  const clean = displayName.replace(/[<>&"']/g, "").trim();
  if (!clean) return res.status(400).json({ error: "empty name" });
  try {
    await db
      .update(users)
      .set({ displayName: clean })
      .where(eq(users.pubkey, req.pubkey));
    res.json({ ok: true, displayName: clean });
  } catch (e) {
    console.error(`[${req.id}] set name:`, e.message);
    res.status(500).json({ error: "update failed" });
  }
});

app.get("/profile/:pubkey", authMiddleware, async (req, res) => {
  if (!isValidPubkey(req.params.pubkey))
    return res.status(400).json({ error: "invalid pubkey" });
  try {
    const [user] = await db
      .select({ displayName: users.displayName })
      .from(users)
      .where(eq(users.pubkey, req.params.pubkey))
      .limit(1);
    res.json({ displayName: user?.displayName || null });
  } catch (e) {
    console.error(`[${req.id}] get profile:`, e.message);
    res.status(500).json({ error: "fetch failed" });
  }
});

app.get("/keys/count", authMiddleware, async (req, res) => {
  try {
    const [row] = await db
      .select({ count: sql`count(*)::int` })
      .from(oneTimePrekeys)
      .where(and(eq(oneTimePrekeys.pubkey, req.pubkey), eq(oneTimePrekeys.used, false)));
    res.json({ count: row?.count || 0 });
  } catch (e) {
    console.error(`[${req.id}] key count:`, e.message);
    res.status(500).json({ error: "count failed" });
  }
});

app.post("/keys/replenish", authMiddleware, async (req, res) => {
  const { oneTimePrekeys: otps } = req.body;
  if (!Array.isArray(otps) || otps.length === 0 || otps.length > 100)
    return res.status(400).json({ error: "invalid prekeys" });
  try {
    const rows = otps
      .filter(
        (k) =>
          typeof k.id === "number" &&
          typeof k.publicKey === "string" &&
          k.publicKey.length <= 128,
      )
      .map((k) => ({
        id: `${req.pubkey}:${k.id}`,
        pubkey: req.pubkey,
        prekeyIndex: k.id,
        publicKey: k.publicKey,
        used: false,
      }));
    if (rows.length)
      await db.insert(oneTimePrekeys).values(rows).onConflictDoNothing();
    res.json({ ok: true, added: rows.length });
  } catch (e) {
    console.error(`[${req.id}] replenish:`, e.message);
    res.status(500).json({ error: "replenish failed" });
  }
});

app.get("/messages/pending", authMiddleware, async (req, res) => {
  try {
    const pending = await db
      .select()
      .from(messages)
      .where(
        and(eq(messages.toPubkey, req.pubkey), eq(messages.delivered, false)),
      )
      .limit(100);
    if (pending.length) {
      await db
        .update(messages)
        .set({ delivered: true })
        .where(
          and(eq(messages.toPubkey, req.pubkey), eq(messages.delivered, false)),
        );
    }
    res.json({ messages: pending });
  } catch (e) {
    console.error(`[${req.id}] pending msgs:`, e.message);
    res.status(500).json({ error: "fetch failed" });
  }
});

app.use((err, req, res, _next) => {
  console.error(`[${req.id}] unhandled:`, err.message);
  res.status(500).json({ error: "internal error" });
});

app.use((_req, res) => {
  res.status(404).json({ error: "not found" });
});

const server = createServer(app);
const wss = new WebSocketServer({
  server,
  maxPayload: WS_MAX_MSG,
  perMessageDeflate: false,
});

function broadcast(sender, data) {
  const raw = JSON.stringify(data);
  for (const [pk, ws] of sockets) {
    if (pk !== sender && ws.readyState === 1) ws.send(raw);
  }
}

function getWsIp(req) {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.socket?.remoteAddress ||
    "unknown"
  );
}

wss.on("connection", (ws, req) => {
  const ip = getWsIp(req);

  const ipCount = (wsPerIp.get(ip) || 0) + 1;
  if (ipCount > WS_MAX_CONNECTIONS_PER_IP) {
    ws.close(4429, "too many connections");
    return;
  }
  wsPerIp.set(ip, ipCount);

  const url = new URL(req.url, `http://${req.headers.host}`);
  const payload = verifyToken(url.searchParams.get("token"));
  if (!payload) {
    wsPerIp.set(ip, (wsPerIp.get(ip) || 1) - 1);
    ws.close(4001, "unauthorized");
    return;
  }

  const pubkey = payload.sub;
  const encPub = url.searchParams.get("encPub");

  if (encPub && !ENCPUB_PATTERN.test(encPub)) {
    wsPerIp.set(ip, (wsPerIp.get(ip) || 1) - 1);
    ws.close(4003, "invalid encPub");
    return;
  }

  if (sockets.has(pubkey)) {
    sockets.get(pubkey).close(4002, "superseded");
  }

  sockets.set(pubkey, ws);
  if (encPub) encPubs.set(pubkey, encPub);

  broadcast(pubkey, {
    type: "user_joined",
    pubkey,
    encPub: encPub || null,
    ts: Date.now(),
  });

  for (const [pk, ep] of encPubs) {
    if (pk !== pubkey)
      ws.send(JSON.stringify({ type: "key_announce", from: pk, encPub: ep }));
  }

  let msgTimestamps = [];

  ws.on("message", async (raw) => {
    const now = Date.now();
    msgTimestamps = msgTimestamps.filter((t) => now - t < WS_MSG_RATE.window);
    if (msgTimestamps.length >= WS_MSG_RATE.max) {
      ws.send(JSON.stringify({ type: "error", error: "slow down" }));
      return;
    }
    msgTimestamps.push(now);

    try {
      const msg = JSON.parse(raw);
      if (!msg || typeof msg !== "object" || !msg.type) return;

      if (msg.type === "key_announce") {
        if (typeof msg.encPub !== "string" || !ENCPUB_PATTERN.test(msg.encPub))
          return;
        encPubs.set(pubkey, msg.encPub);
        broadcast(pubkey, {
          type: "key_announce",
          from: pubkey,
          encPub: msg.encPub,
        });
        return;
      }

      if (msg.type === "x3dh_init") {
        if (!msg.to || typeof msg.to !== "string" || !isValidPubkey(msg.to))
          return;
        if (
          !msg.identityKey ||
          !msg.ephemeralKey ||
          typeof msg.header !== "object"
        )
          return;
        const target = sockets.get(msg.to);
        if (target?.readyState === 1) {
          target.send(
            JSON.stringify({
              type: "x3dh_init",
              from: pubkey,
              identityKey: msg.identityKey,
              ephemeralKey: msg.ephemeralKey,
              usedOnePrekeyId: msg.usedOnePrekeyId ?? null,
              header: msg.header,
              nonce: msg.nonce,
              ciphertext: msg.ciphertext,
            }),
          );
        }
        return;
      }

      if (msg.type === "typing") {
        if (!msg.to || typeof msg.to !== "string") return;
        const target = sockets.get(msg.to);
        if (target?.readyState === 1)
          target.send(
            JSON.stringify({
              type: "typing",
              from: pubkey,
              active: !!msg.active,
            }),
          );
        return;
      }

      if (msg.type === "read") {
        if (!msg.to || typeof msg.to !== "string" || !msg.msgId) return;
        const target = sockets.get(msg.to);
        if (target?.readyState === 1)
          target.send(
            JSON.stringify({ type: "read", from: pubkey, msgId: msg.msgId }),
          );
        return;
      }

      if (msg.type !== "chat") return;

      if (
        !msg.recipients ||
        !Array.isArray(msg.recipients) ||
        msg.recipients.length === 0
      ) {
        ws.send(
          JSON.stringify({ type: "error", error: "e2e encryption required" }),
        );
        return;
      }

      if (msg.recipients.length > 100) return;

      const msgId = uid();
      const ts = Date.now();

      for (const r of msg.recipients) {
        if (!r.to || typeof r.to !== "string") continue;
        if (!r.nonce || !r.ciphertext) continue;
        if (typeof r.nonce !== "string" || typeof r.ciphertext !== "string")
          continue;
        if (r.nonce.length > 128 || r.ciphertext.length > 16384) continue;

        const payload = {
          type: "chat",
          id: msgId,
          from: pubkey,
          nonce: r.nonce,
          ciphertext: r.ciphertext,
          ts,
        };
        if (r.header && typeof r.header === "object") payload.header = r.header;

        if (sockets.has(r.to) && sockets.get(r.to).readyState === 1) {
          sockets.get(r.to).send(JSON.stringify(payload));
        } else {
          try {
            await db.insert(messages).values({
              id: `${msgId}:${r.to}`,
              fromPubkey: pubkey,
              toPubkey: r.to,
              ciphertext: JSON.stringify({
                nonce: r.nonce,
                ciphertext: r.ciphertext,
                header: r.header || null,
              }),
              delivered: false,
            });
          } catch {}
        }
      }

      ws.send(JSON.stringify({ type: "chat_ack", id: msgId, ts }));

      try {
        await db.insert(messages).values({
          id: msgId,
          fromPubkey: pubkey,
          toPubkey: null,
          ciphertext: `[e2e:${msg.recipients.length}]`,
        });
      } catch (e) {
        console.error(`[ws] db insert:`, e.message);
      }
    } catch {}
  });

  ws.on("close", () => {
    sockets.delete(pubkey);
    encPubs.delete(pubkey);
    const count = (wsPerIp.get(ip) || 1) - 1;
    if (count <= 0) wsPerIp.delete(ip);
    else wsPerIp.set(ip, count);
    broadcast(pubkey, { type: "user_left", pubkey, ts: Date.now() });
  });

  ws.on("error", () => ws.terminate());
});

function shutdown() {
  console.log("shutting down...");
  wss.clients.forEach((ws) => ws.close(1001, "server restarting"));
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 5000);
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

server.listen(PORT, () =>
  console.log(`torvex api on :${PORT} (${IS_PROD ? "prod" : "dev"})`),
);
