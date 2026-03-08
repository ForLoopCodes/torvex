// torvex web - double ratchet encrypted chat
// x3dh session init, per-peer ratchet states, forward secrecy

import React, { useState, useEffect, useRef, useCallback } from "react";
import bs58 from "bs58";
import { generateEphemeralKey, x3dhInitiator, x3dhResponder } from "../crypto/x3dh.js";
import { initSender, initReceiver, ratchetEncrypt, ratchetDecrypt, serializeState, deserializeState } from "../crypto/ratchet.js";

const WS_URL = import.meta.env.VITE_WS_URL || "ws://localhost:4400";
const API = import.meta.env.VITE_API_URL || "http://localhost:4400";
const STORAGE_PREFIX = "torvex_ratchet_";

function shortKey(pk) {
  return pk.slice(0, 4) + "..." + pk.slice(-4);
}

function loadRatchetState(myPubkey, peerPubkey) {
  try {
    const raw = sessionStorage.getItem(`${STORAGE_PREFIX}${myPubkey}:${peerPubkey}`);
    return raw ? deserializeState(raw) : null;
  } catch { return null; }
}

function saveRatchetState(myPubkey, peerPubkey, state) {
  try {
    sessionStorage.setItem(`${STORAGE_PREFIX}${myPubkey}:${peerPubkey}`, serializeState(state));
  } catch {}
}

function clearRatchetStates(myPubkey) {
  for (let i = sessionStorage.length - 1; i >= 0; i--) {
    const key = sessionStorage.key(i);
    if (key?.startsWith(`${STORAGE_PREFIX}${myPubkey}:`)) sessionStorage.removeItem(key);
  }
}

async function fetchPrekeyBundle(token, pubkey) {
  const res = await fetch(`${API}/keys/bundle/${pubkey}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) return null;
  const data = await res.json();
  return {
    identityKey: bs58.decode(data.identityKey),
    signedPrekey: bs58.decode(data.signedPrekey),
    signedPrekeySignature: bs58.decode(data.signedPrekeySig),
    usedOneTimePrekey: data.oneTimePrekey ? bs58.decode(data.oneTimePrekey.publicKey) : null,
    usedOnePrekeyId: data.oneTimePrekey?.id ?? null,
  };
}

export default function Chat({ session, onLogout }) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [onlineUsers, setOnlineUsers] = useState([]);
  const [activePeer, setActivePeer] = useState(null);
  const wsRef = useRef(null);
  const bottomRef = useRef(null);
  const ratchetsRef = useRef(new Map());
  const pendingRef = useRef(new Map());
  const initializingRef = useRef(new Set());

  const hasRatchetKeys = !!session.keys?.identity && !!session.keys?.encryption;

  const getRatchet = useCallback((peerPubkey) => {
    if (ratchetsRef.current.has(peerPubkey)) return ratchetsRef.current.get(peerPubkey);
    const loaded = loadRatchetState(session.pubkey, peerPubkey);
    if (loaded) {
      ratchetsRef.current.set(peerPubkey, loaded);
      return loaded;
    }
    return null;
  }, [session.pubkey]);

  const setRatchet = useCallback((peerPubkey, state) => {
    ratchetsRef.current.set(peerPubkey, state);
    saveRatchetState(session.pubkey, peerPubkey, state);
  }, [session.pubkey]);

  const initSessionWithPeer = useCallback(async (peerPubkey) => {
    if (!hasRatchetKeys || initializingRef.current.has(peerPubkey) || getRatchet(peerPubkey)) return;
    initializingRef.current.add(peerPubkey);

    try {
      const bundle = await fetchPrekeyBundle(session.token, peerPubkey);
      if (!bundle) {
        setMessages((prev) => [...prev, { id: Date.now().toString(), from: "system", text: `${shortKey(peerPubkey)} has no prekey bundle`, ts: Date.now() }]);
        return;
      }

      const ephemeral = generateEphemeralKey();
      const { sharedSecret, usedOnePrekeyId } = x3dhInitiator(session.keys.identity, ephemeral, bundle);
      const state = initSender(sharedSecret, bundle.signedPrekey);
      setRatchet(peerPubkey, state);

      const initMsg = ratchetEncrypt(state, "session established");
      setRatchet(peerPubkey, state);

      wsRef.current?.send(JSON.stringify({
        type: "x3dh_init",
        to: peerPubkey,
        identityKey: bs58.encode(session.keys.identity.publicKey),
        ephemeralKey: bs58.encode(ephemeral.publicKey),
        usedOnePrekeyId,
        header: initMsg.header,
        nonce: initMsg.nonce,
        ciphertext: initMsg.ciphertext,
      }));

      setMessages((prev) => [...prev, { id: Date.now().toString(), from: "system", text: `ratchet session started with ${shortKey(peerPubkey)}`, ts: Date.now() }]);
    } catch (err) {
      console.error("x3dh init failed:", err.message);
      setMessages((prev) => [...prev, { id: Date.now().toString(), from: "system", text: `session setup failed: ${err.message}`, ts: Date.now() }]);
    } finally {
      initializingRef.current.delete(peerPubkey);
    }
  }, [session, hasRatchetKeys, getRatchet, setRatchet]);

  const handleMsg = useCallback((e) => {
    const msg = JSON.parse(e.data);

    if (msg.type === "user_joined") {
      setOnlineUsers((prev) => [...new Set([...prev, msg.pubkey])]);
    } else if (msg.type === "user_left") {
      setOnlineUsers((prev) => prev.filter((u) => u !== msg.pubkey));
    } else if (msg.type === "x3dh_init" && hasRatchetKeys) {
      try {
        const theirIdentity = bs58.decode(msg.identityKey);
        const theirEphemeral = bs58.decode(msg.ephemeralKey);
        const mySignedPrekey = session.signedPrekey?.keyPair;
        const myOtp = msg.usedOnePrekeyId != null
          ? session.oneTimePrekeys?.find((k) => k.id === msg.usedOnePrekeyId)?.keyPair
          : null;

        const sharedSecret = x3dhResponder(session.keys.identity, mySignedPrekey, myOtp || null, theirIdentity, theirEphemeral);
        const state = initReceiver(sharedSecret, mySignedPrekey);
        const text = ratchetDecrypt(state, msg.header, msg.nonce, msg.ciphertext);
        setRatchet(msg.from, state);

        setMessages((prev) => [...prev, { id: Date.now().toString(), from: "system", text: `ratchet session with ${shortKey(msg.from)}: ${text}`, ts: Date.now() }]);
      } catch (err) {
        console.error("x3dh respond failed:", err.message);
      }
    } else if (msg.type === "chat") {
      let text = "[encrypted — no session]";
      if (msg.header) {
        const state = getRatchet(msg.from);
        if (state) {
          try {
            text = ratchetDecrypt(state, msg.header, msg.nonce, msg.ciphertext);
            setRatchet(msg.from, state);
          } catch { text = "[ratchet decryption failed]"; }
        }
      }
      setMessages((prev) => [...prev, { id: msg.id, from: msg.from, text, ts: msg.ts }]);
    } else if (msg.type === "chat_ack") {
      const pending = pendingRef.current.get(msg.id);
      if (pending) {
        pendingRef.current.delete(msg.id);
        setMessages((prev) => [...prev, { id: msg.id, from: session.pubkey, text: pending.text, ts: msg.ts }]);
      }
    } else if (msg.type === "error") {
      console.warn("server:", msg.error);
    }
  }, [session, hasRatchetKeys, getRatchet, setRatchet]);

  useEffect(() => {
    const encPub = session.keys?.encryption ? bs58.encode(session.keys.encryption.publicKey) : "";
    const ws = new WebSocket(`${WS_URL}?token=${session.token}&encPub=${encPub}`);
    wsRef.current = ws;
    ws.onmessage = handleMsg;
    ws.onclose = () => console.log("ws closed");
    return () => { ws.close(); clearRatchetStates(session.pubkey); };
  }, [session.token, handleMsg, session.pubkey, session.keys]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  function send(e) {
    e.preventDefault();
    const text = input.trim();
    if (!text || wsRef.current?.readyState !== 1 || !activePeer) return;

    const state = getRatchet(activePeer);
    if (!state) {
      setMessages((prev) => [...prev, { id: Date.now().toString(), from: "system", text: `no ratchet session with ${shortKey(activePeer)} — click their name to init`, ts: Date.now() }]);
      setInput("");
      return;
    }

    const { header, nonce, ciphertext } = ratchetEncrypt(state, text);
    setRatchet(activePeer, state);

    const tempId = crypto.randomUUID();
    pendingRef.current.set(tempId, { text, peer: activePeer });

    wsRef.current.send(JSON.stringify({
      type: "chat",
      recipients: [{ to: activePeer, header, nonce, ciphertext }],
    }));

    setTimeout(() => {
      if (pendingRef.current.has(tempId)) {
        const p = pendingRef.current.get(tempId);
        pendingRef.current.delete(tempId);
        setMessages((prev) => [...prev, { id: tempId, from: session.pubkey, text: p.text, ts: Date.now() }]);
      }
    }, 3000);

    setInput("");
  }

  const peerMessages = activePeer
    ? messages.filter((m) => m.from === activePeer || (m.from === session.pubkey && pendingRef.current.get(m.id)?.peer === activePeer) || m.from === "system")
    : messages;

  return (
    <div className="chat-layout">
      <aside className="sidebar">
        <div className="sidebar-header">
          <h2>torvex</h2>
          <span className="user-badge" title={session.pubkey}>{shortKey(session.pubkey)}</span>
        </div>
        <div className="online-list">
          <h3>online — e2e encrypted</h3>
          {onlineUsers.length === 0 && <p className="muted">no one else here yet</p>}
          {onlineUsers.map((u) => (
            <div
              key={u}
              className={`online-user ${activePeer === u ? "active" : ""}`}
              title={u}
              onClick={() => {
                setActivePeer(u);
                if (hasRatchetKeys && !getRatchet(u)) initSessionWithPeer(u);
              }}
            >
              {shortKey(u)} {getRatchet(u) ? "🔒" : "⚠️"}
            </div>
          ))}
        </div>
        <button className="logout-btn" onClick={onLogout}>logout</button>
      </aside>
      <main className="chat-main">
        <div className="messages">
          {!activePeer && (
            <div className="empty-chat"><p>select a peer from the sidebar to start chatting</p></div>
          )}
          {activePeer && peerMessages.length === 0 && (
            <div className="empty-chat"><p>no messages yet with {shortKey(activePeer)}. say something.</p></div>
          )}
          {peerMessages.map((m) => (
            <div key={m.id} className={`msg ${m.from === session.pubkey ? "msg-self" : m.from === "system" ? "msg-system" : "msg-other"}`}>
              <span className="msg-author">{m.from === "system" ? "system" : shortKey(m.from)}</span>
              <span className="msg-text">{m.text}</span>
              <span className="msg-time">{new Date(m.ts).toLocaleTimeString()}</span>
            </div>
          ))}
          <div ref={bottomRef} />
        </div>
        <form className="chat-input" onSubmit={send}>
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={activePeer ? `message ${shortKey(activePeer)}...` : "select a peer first..."}
            disabled={!activePeer}
            autoFocus
          />
          <button type="submit" disabled={!activePeer}>send</button>
        </form>
      </main>
    </div>
  );
}
