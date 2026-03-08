// torchat web - chat view with websocket messaging
// renders message list sidebar and live chat area

import React, { useState, useEffect, useRef } from "react";

const WS_URL = import.meta.env.VITE_WS_URL || "ws://localhost:4400";

function shortKey(pubkey) {
  return pubkey.slice(0, 4) + "..." + pubkey.slice(-4);
}

export default function Chat({ session, onLogout }) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [onlineUsers, setOnlineUsers] = useState([]);
  const wsRef = useRef(null);
  const bottomRef = useRef(null);

  useEffect(() => {
    const ws = new WebSocket(`${WS_URL}?token=${session.token}`);
    wsRef.current = ws;

    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data);
      if (msg.type === "chat") {
        setMessages((prev) => [...prev, msg]);
      } else if (msg.type === "user_joined") {
        setOnlineUsers((prev) => [...new Set([...prev, msg.pubkey])]);
      } else if (msg.type === "user_left") {
        setOnlineUsers((prev) => prev.filter((u) => u !== msg.pubkey));
      }
    };

    ws.onclose = () => console.log("ws closed");
    return () => ws.close();
  }, [session.token]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  function send(e) {
    e.preventDefault();
    if (!input.trim() || wsRef.current?.readyState !== 1) return;
    wsRef.current.send(JSON.stringify({ type: "chat", text: input }));
    setInput("");
  }

  return (
    <div className="chat-layout">
      <aside className="sidebar">
        <div className="sidebar-header">
          <h2>torchat</h2>
          <span className="user-badge" title={session.pubkey}>
            {shortKey(session.pubkey)}
          </span>
        </div>
        <div className="online-list">
          <h3>online</h3>
          {onlineUsers.length === 0 && (
            <p className="muted">no one else here yet</p>
          )}
          {onlineUsers.map((u) => (
            <div key={u} className="online-user" title={u}>
              {shortKey(u)}
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
              className={`msg ${m.from === session.pubkey ? "msg-self" : "msg-other"}`}
            >
              <span className="msg-author">{shortKey(m.from)}</span>
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
