// torchat api - websocket signaling server
// handles auth, rooms, and realtime message relay

import { createServer } from "http";
import express from "express";
import cors from "cors";
import { WebSocketServer } from "ws";
import { v4 as uid } from "uuid";

const PORT = process.env.PORT || 4400;
const app = express();
app.use(cors());
app.use(express.json());

const users = new Map();
const sockets = new Map();

app.post("/auth/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: "missing fields" });
  if (users.has(username))
    return res.status(409).json({ error: "username taken" });
  const token = uid();
  users.set(username, { password, token });
  res.json({ token, username });
});

app.post("/auth/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.get(username);
  if (!user || user.password !== password)
    return res.status(401).json({ error: "invalid credentials" });
  const token = uid();
  user.token = token;
  res.json({ token, username });
});

const server = createServer(app);
const wss = new WebSocketServer({ server });

function findToken(req) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  return url.searchParams.get("token");
}

function findUser(token) {
  for (const [username, data] of users) {
    if (data.token === token) return username;
  }
  return null;
}

function broadcast(sender, payload) {
  for (const [username, ws] of sockets) {
    if (username !== sender && ws.readyState === 1) {
      ws.send(JSON.stringify(payload));
    }
  }
}

wss.on("connection", (ws, req) => {
  const token = findToken(req);
  const username = findUser(token);

  if (!username) {
    ws.close(4001, "unauthorized");
    return;
  }

  sockets.set(username, ws);
  broadcast(username, { type: "user_joined", username, ts: Date.now() });

  ws.on("message", (raw) => {
    try {
      const msg = JSON.parse(raw);
      if (msg.type === "chat") {
        const payload = {
          type: "chat",
          id: uid(),
          from: username,
          to: msg.to || null,
          text: msg.text,
          ts: Date.now(),
        };

        if (msg.to && sockets.has(msg.to)) {
          sockets.get(msg.to).send(JSON.stringify(payload));
          ws.send(JSON.stringify(payload));
        } else {
          broadcast(username, payload);
          ws.send(JSON.stringify(payload));
        }
      }
    } catch {}
  });

  ws.on("close", () => {
    sockets.delete(username);
    broadcast(username, { type: "user_left", username, ts: Date.now() });
  });
});

server.listen(PORT, () => console.log(`torchat api running on :${PORT}`));
