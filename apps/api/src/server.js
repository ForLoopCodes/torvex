// torvex api - websocket signaling server with wallet auth
// challenge-response ed25519 auth, drizzle persistence, ws relay

import "dotenv/config";
import { createServer } from "http";
import express from "express";
import cors from "cors";
import { WebSocketServer } from "ws";
import { v4 as uid } from "uuid";
import nacl from "tweetnacl";
import bs58 from "bs58";
import { db } from "./db/index.js";
import { users, messages } from "./db/schema.js";
import { eq } from "drizzle-orm";

const PORT = process.env.PORT || 4400;
const app = express();
app.use(cors());
app.use(express.json());

const challenges = new Map();
const tokens = new Map();
const sockets = new Map();

app.post("/auth/challenge", (req, res) => {
  const { pubkey } = req.body;
  if (!pubkey) return res.status(400).json({ error: "missing pubkey" });
  const challenge = uid() + "-" + Date.now();
  challenges.set(pubkey, challenge);
  setTimeout(() => challenges.delete(pubkey), 60000);
  res.json({ challenge });
});

app.post("/auth/verify", async (req, res) => {
  const { pubkey, signature } = req.body;
  if (!pubkey || !signature)
    return res.status(400).json({ error: "missing fields" });

  const challenge = challenges.get(pubkey);
  if (!challenge)
    return res.status(401).json({ error: "no pending challenge" });

  try {
    const sigBytes = bs58.decode(signature);
    const msgBytes = new TextEncoder().encode(challenge);
    const pubBytes = bs58.decode(pubkey);

    if (!nacl.sign.detached.verify(msgBytes, sigBytes, pubBytes)) {
      return res.status(401).json({ error: "invalid signature" });
    }

    challenges.delete(pubkey);
    const token = uid();
    tokens.set(token, pubkey);

    try {
      await db.insert(users).values({ pubkey }).onConflictDoNothing();
    } catch {}

    res.json({ token, pubkey });
  } catch (err) {
    res.status(400).json({ error: "verification failed" });
  }
});

app.get("/auth/me", (req, res) => {
  const token = req.headers.authorization?.replace("Bearer ", "");
  const pubkey = tokens.get(token);
  if (!pubkey) return res.status(401).json({ error: "unauthorized" });
  res.json({ pubkey });
});

const server = createServer(app);
const wss = new WebSocketServer({ server });

function broadcast(sender, payload) {
  for (const [pubkey, ws] of sockets) {
    if (pubkey !== sender && ws.readyState === 1) {
      ws.send(JSON.stringify(payload));
    }
  }
}

wss.on("connection", (ws, req) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const token = url.searchParams.get("token");
  const pubkey = tokens.get(token);

  if (!pubkey) {
    ws.close(4001, "unauthorized");
    return;
  }

  sockets.set(pubkey, ws);
  broadcast(pubkey, { type: "user_joined", pubkey, ts: Date.now() });

  ws.on("message", async (raw) => {
    try {
      const msg = JSON.parse(raw);
      if (msg.type === "chat") {
        const payload = {
          type: "chat",
          id: uid(),
          from: pubkey,
          to: msg.to || null,
          text: msg.text,
          ts: Date.now(),
        };

        if (msg.to && sockets.has(msg.to)) {
          sockets.get(msg.to).send(JSON.stringify(payload));
          ws.send(JSON.stringify(payload));
        } else {
          broadcast(pubkey, payload);
          ws.send(JSON.stringify(payload));
        }

        try {
          await db.insert(messages).values({
            id: payload.id,
            fromPubkey: pubkey,
            toPubkey: msg.to || null,
            ciphertext: msg.text,
          });
        } catch {}
      }
    } catch {}
  });

  ws.on("close", () => {
    sockets.delete(pubkey);
    broadcast(pubkey, { type: "user_left", pubkey, ts: Date.now() });
  });
});

server.listen(PORT, () => console.log(`torvex api running on :${PORT}`));
