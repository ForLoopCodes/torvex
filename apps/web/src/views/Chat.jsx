// torvex web - e2e encrypted chat with websocket
// nacl.box encryption, key exchange, client-side only decrypt

import React, { useState, useEffect, useRef, useCallback } from "react";
import nacl from "tweetnacl";
import bs58 from "bs58";

const WS_URL = import.meta.env.VITE_WS_URL || "ws://localhost:4400";

function shortKey(pk) {
  return pk.slice(0, 4) + "..." + pk.slice(-4);
}

function encryptFor(text, recipientPub, senderSecret) {
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  return {
    nonce: bs58.encode(nonce),
    ciphertext: bs58.encode(
      nacl.box(
        new TextEncoder().encode(text),
        nonce,
        recipientPub,
        senderSecret,
      ),
    ),
  };
}

function decryptFrom(ciphertext, nonce, senderPub, mySecret) {
  const plain = nacl.box.open(
    bs58.decode(ciphertext),
    bs58.decode(nonce),
    senderPub,
    mySecret,
  );
  return plain ? new TextDecoder().decode(plain) : null;
}

export default function Chat({ session, onLogout }) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [onlineUsers, setOnlineUsers] = useState([]);
  const wsRef = useRef(null);
  const bottomRef = useRef(null);
  const peerKeysRef = useRef(new Map());
  const pendingRef = useRef(new Map());
  const encPubB58 = useRef(bs58.encode(session.encryptKeys.publicKey));

  const handleMsg = useCallback(
    (e) => {
      const msg = JSON.parse(e.data);

      if (msg.type === "user_joined") {
        setOnlineUsers((prev) => [...new Set([...prev, msg.pubkey])]);
        if (msg.encPub)
          peerKeysRef.current.set(msg.pubkey, bs58.decode(msg.encPub));
        wsRef.current?.send(
          JSON.stringify({ type: "key_announce", encPub: encPubB58.current }),
        );
      } else if (msg.type === "user_left") {
        setOnlineUsers((prev) => prev.filter((u) => u !== msg.pubkey));
        peerKeysRef.current.delete(msg.pubkey);
      } else if (msg.type === "key_announce") {
        if (msg.from && msg.encPub)
          peerKeysRef.current.set(msg.from, bs58.decode(msg.encPub));
      } else if (msg.type === "chat") {
        const senderPub = peerKeysRef.current.get(msg.from);
        let text = "[encrypted — missing key]";
        if (senderPub && msg.nonce && msg.ciphertext) {
          text =
            decryptFrom(
              msg.ciphertext,
              msg.nonce,
              senderPub,
              session.encryptKeys.secretKey,
            ) || "[decryption failed]";
        }
        setMessages((prev) => [
          ...prev,
          { id: msg.id, from: msg.from, text, ts: msg.ts },
        ]);
      } else if (msg.type === "chat_ack") {
        const pending = pendingRef.current.get(msg.id);
        if (pending) {
          pendingRef.current.delete(msg.id);
          setMessages((prev) => [
            ...prev,
            { id: msg.id, from: session.pubkey, text: pending, ts: msg.ts },
          ]);
        }
      } else if (msg.type === "error") {
        console.warn("server:", msg.error);
      }
    },
    [session],
  );

  useEffect(() => {
    const ws = new WebSocket(
      `${WS_URL}?token=${session.token}&encPub=${encPubB58.current}`,
    );
    wsRef.current = ws;
    ws.onmessage = handleMsg;
    ws.onclose = () => console.log("ws closed");
    return () => ws.close();
  }, [session.token, handleMsg]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  function send(e) {
    e.preventDefault();
    const text = input.trim();
    if (!text || wsRef.current?.readyState !== 1) return;

    const peers = Array.from(peerKeysRef.current.entries());
    if (peers.length === 0) {
      setMessages((prev) => [
        ...prev,
        {
          id: Date.now().toString(),
          from: "system",
          text: "no peers online to encrypt for",
          ts: Date.now(),
        },
      ]);
      setInput("");
      return;
    }

    const recipients = peers.map(([pubkey, encPub]) => ({
      to: pubkey,
      ...encryptFor(text, encPub, session.encryptKeys.secretKey),
    }));
    const tempId = crypto.randomUUID();
    pendingRef.current.set(tempId, text);

    wsRef.current.send(JSON.stringify({ type: "chat", recipients }));

    setTimeout(() => {
      if (pendingRef.current.has(tempId)) {
        pendingRef.current.delete(tempId);
        setMessages((prev) => [
          ...prev,
          { id: tempId, from: session.pubkey, text, ts: Date.now() },
        ]);
      }
    }, 3000);

    setInput("");
  }

  return (
    <div className="chat-layout">
      <aside className="sidebar">
        <div className="sidebar-header">
          <h2>torvex</h2>
          <span className="user-badge" title={session.pubkey}>
            {shortKey(session.pubkey)}
          </span>
        </div>
        <div className="online-list">
          <h3>online — e2e encrypted</h3>
          {onlineUsers.length === 0 && (
            <p className="muted">no one else here yet</p>
          )}
          {onlineUsers.map((u) => (
            <div key={u} className="online-user" title={u}>
              {shortKey(u)} {peerKeysRef.current.has(u) ? "🔒" : "⚠️"}
            </div>
          ))}
        </div>
        <button className="logout-btn" onClick={onLogout}>
          logout
        </button>
      </aside>
      <main className="chat-main">
        <div className="messages">
          {messages.length === 0 && (
            <div className="empty-chat">
              <p>no messages yet. say something.</p>
            </div>
          )}
          {messages.map((m) => (
            <div
              key={m.id}
              className={`msg ${m.from === session.pubkey ? "msg-self" : m.from === "system" ? "msg-system" : "msg-other"}`}
            >
              <span className="msg-author">
                {m.from === "system" ? "system" : shortKey(m.from)}
              </span>
              <span className="msg-text">{m.text}</span>
              <span className="msg-time">
                {new Date(m.ts).toLocaleTimeString()}
              </span>
            </div>
          ))}
          <div ref={bottomRef} />
        </div>
        <form className="chat-input" onSubmit={send}>
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="type a message..."
            autoFocus
          />
          <button type="submit">send</button>
        </form>
      </main>
    </div>
  );
}
