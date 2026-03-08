// torvex web - double ratchet encrypted chat
// typing indicators, read receipts, offline delivery, display names

import React, { useState, useEffect, useRef, useCallback } from "react";
import bs58 from "bs58";
import {
  generateEphemeralKey,
  x3dhInitiator,
  x3dhResponder,
} from "../crypto/x3dh.js";
import {
  initSender,
  initReceiver,
  ratchetEncrypt,
  ratchetDecrypt,
  serializeState,
  deserializeState,
} from "../crypto/ratchet.js";

const WS_URL = import.meta.env.VITE_WS_URL || "ws://localhost:4400";
const API = import.meta.env.VITE_API_URL || "http://localhost:4400";
const STORAGE_PREFIX = "torvex_ratchet_";
const TYPING_TIMEOUT = 2000;

function shortKey(pk) {
  return pk.slice(0, 4) + "..." + pk.slice(-4);
}

function loadRatchetState(myPk, peerPk) {
  try {
    const raw = sessionStorage.getItem(`${STORAGE_PREFIX}${myPk}:${peerPk}`);
    return raw ? deserializeState(raw) : null;
  } catch {
    return null;
  }
}

function saveRatchetState(myPk, peerPk, state) {
  try {
    sessionStorage.setItem(
      `${STORAGE_PREFIX}${myPk}:${peerPk}`,
      serializeState(state),
    );
  } catch {}
}

async function fetchPrekeyBundle(token, pubkey) {
  const res = await fetch(`${API}/keys/bundle/${pubkey}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) return null;
  const d = await res.json();
  return {
    identityKey: bs58.decode(d.identityKey),
    signedPrekey: bs58.decode(d.signedPrekey),
    signedPrekeySignature: bs58.decode(d.signedPrekeySig),
    usedOneTimePrekey: d.oneTimePrekey
      ? bs58.decode(d.oneTimePrekey.publicKey)
      : null,
    usedOnePrekeyId: d.oneTimePrekey?.id ?? null,
  };
}

async function fetchPendingMessages(token) {
  const res = await fetch(`${API}/messages/pending`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) return [];
  const { messages } = await res.json();
  return messages || [];
}

async function fetchDisplayName(token, pubkey) {
  try {
    const res = await fetch(`${API}/profile/${pubkey}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) return null;
    const { displayName } = await res.json();
    return displayName;
  } catch {
    return null;
  }
}

async function setDisplayName(token, name) {
  const res = await fetch(`${API}/profile/name`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ displayName: name }),
  });
  return res.ok ? (await res.json()).displayName : null;
}

export default function Chat({ session, onLogout }) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [onlineUsers, setOnlineUsers] = useState([]);
  const [activePeer, setActivePeer] = useState(null);
  const [peerNames, setPeerNames] = useState({});
  const [myName, setMyName] = useState("");
  const [nameInput, setNameInput] = useState("");
  const [showNameEdit, setShowNameEdit] = useState(false);
  const [typingPeers, setTypingPeers] = useState(new Set());
  const [readReceipts, setReadReceipts] = useState({});
  const [addPeerInput, setAddPeerInput] = useState("");
  const [contacts, setContacts] = useState(() => {
    try {
      return JSON.parse(
        localStorage.getItem(`torvex_contacts_${session.pubkey}`) || "[]",
      );
    } catch {
      return [];
    }
  });

  const wsRef = useRef(null);
  const bottomRef = useRef(null);
  const ratchetsRef = useRef(new Map());
  const pendingRef = useRef(new Map());
  const initializingRef = useRef(new Set());
  const typingTimerRef = useRef(null);
  const lastTypingSentRef = useRef(0);

  const hasRatchetKeys = !!session.keys?.identity && !!session.keys?.encryption;

  useEffect(() => {
    localStorage.setItem(
      `torvex_contacts_${session.pubkey}`,
      JSON.stringify(contacts),
    );
  }, [contacts, session.pubkey]);

  const getRatchet = useCallback(
    (peerPk) => {
      if (ratchetsRef.current.has(peerPk))
        return ratchetsRef.current.get(peerPk);
      const loaded = loadRatchetState(session.pubkey, peerPk);
      if (loaded) {
        ratchetsRef.current.set(peerPk, loaded);
        return loaded;
      }
      return null;
    },
    [session.pubkey],
  );

  const setRatchet = useCallback(
    (peerPk, state) => {
      ratchetsRef.current.set(peerPk, state);
      saveRatchetState(session.pubkey, peerPk, state);
    },
    [session.pubkey],
  );

  const resolveDisplayName = useCallback(
    async (pubkey) => {
      if (peerNames[pubkey]) return;
      const name = await fetchDisplayName(session.token, pubkey);
      if (name) setPeerNames((prev) => ({ ...prev, [pubkey]: name }));
    },
    [session.token, peerNames],
  );

  const peerLabel = useCallback(
    (pk) => peerNames[pk] || shortKey(pk),
    [peerNames],
  );

  const initSessionWithPeer = useCallback(
    async (peerPk) => {
      if (
        !hasRatchetKeys ||
        initializingRef.current.has(peerPk) ||
        getRatchet(peerPk)
      )
        return;
      initializingRef.current.add(peerPk);
      try {
        const bundle = await fetchPrekeyBundle(session.token, peerPk);
        if (!bundle) {
          setMessages((prev) => [
            ...prev,
            {
              id: Date.now().toString(),
              from: "system",
              text: `${peerLabel(peerPk)} has no prekey bundle`,
              ts: Date.now(),
            },
          ]);
          return;
        }
        const ephemeral = generateEphemeralKey();
        const { sharedSecret, usedOnePrekeyId } = x3dhInitiator(
          session.keys.identity,
          ephemeral,
          bundle,
        );
        const state = initSender(sharedSecret, bundle.signedPrekey);
        setRatchet(peerPk, state);
        const initMsg = ratchetEncrypt(state, "session established");
        setRatchet(peerPk, state);
        wsRef.current?.send(
          JSON.stringify({
            type: "x3dh_init",
            to: peerPk,
            identityKey: bs58.encode(session.keys.identity.publicKey),
            ephemeralKey: bs58.encode(ephemeral.publicKey),
            usedOnePrekeyId,
            header: initMsg.header,
            nonce: initMsg.nonce,
            ciphertext: initMsg.ciphertext,
          }),
        );
        setMessages((prev) => [
          ...prev,
          {
            id: Date.now().toString(),
            from: "system",
            text: `ratchet session started with ${peerLabel(peerPk)}`,
            ts: Date.now(),
          },
        ]);
      } catch (err) {
        setMessages((prev) => [
          ...prev,
          {
            id: Date.now().toString(),
            from: "system",
            text: `session setup failed: ${err.message}`,
            ts: Date.now(),
          },
        ]);
      } finally {
        initializingRef.current.delete(peerPk);
      }
    },
    [session, hasRatchetKeys, getRatchet, setRatchet, peerLabel],
  );

  const handleMsg = useCallback(
    (e) => {
      const msg = JSON.parse(e.data);

      if (msg.type === "user_joined") {
        setOnlineUsers((prev) => [...new Set([...prev, msg.pubkey])]);
        resolveDisplayName(msg.pubkey);
      } else if (msg.type === "user_left") {
        setOnlineUsers((prev) => prev.filter((u) => u !== msg.pubkey));
        setTypingPeers((prev) => {
          const n = new Set(prev);
          n.delete(msg.pubkey);
          return n;
        });
      } else if (msg.type === "x3dh_init" && hasRatchetKeys) {
        try {
          const theirIdentity = bs58.decode(msg.identityKey);
          const theirEphemeral = bs58.decode(msg.ephemeralKey);
          const myOtp =
            msg.usedOnePrekeyId != null
              ? session.oneTimePrekeys?.find(
                  (k) => k.id === msg.usedOnePrekeyId,
                )?.keyPair
              : null;
          const sharedSecret = x3dhResponder(
            session.keys.identity,
            session.signedPrekey?.keyPair,
            myOtp || null,
            theirIdentity,
            theirEphemeral,
          );
          const state = initReceiver(
            sharedSecret,
            session.signedPrekey?.keyPair,
          );
          ratchetDecrypt(state, msg.header, msg.nonce, msg.ciphertext);
          setRatchet(msg.from, state);
          resolveDisplayName(msg.from);
          setMessages((prev) => [
            ...prev,
            {
              id: Date.now().toString(),
              from: "system",
              text: `ratchet session established with ${shortKey(msg.from)}`,
              ts: Date.now(),
            },
          ]);
        } catch (err) {
          console.error("x3dh respond failed:", err.message);
        }
      } else if (msg.type === "chat") {
        let text = "[encrypted — no session]";
        if (msg.header) {
          const state = getRatchet(msg.from);
          if (state) {
            try {
              text = ratchetDecrypt(
                state,
                msg.header,
                msg.nonce,
                msg.ciphertext,
              );
              setRatchet(msg.from, state);
            } catch {
              text = "[ratchet decryption failed]";
            }
          }
        }
        setMessages((prev) => [
          ...prev,
          { id: msg.id, from: msg.from, text, ts: msg.ts, read: false },
        ]);
        if (wsRef.current?.readyState === 1)
          wsRef.current.send(
            JSON.stringify({ type: "read", to: msg.from, msgId: msg.id }),
          );
      } else if (msg.type === "chat_ack") {
        const pending = pendingRef.current.get(msg.id);
        if (pending) {
          pendingRef.current.delete(msg.id);
          setMessages((prev) => [
            ...prev,
            {
              id: msg.id,
              from: session.pubkey,
              text: pending.text,
              ts: msg.ts,
              peer: pending.peer,
              read: false,
            },
          ]);
        }
      } else if (msg.type === "typing") {
        if (msg.active) {
          setTypingPeers((prev) => new Set(prev).add(msg.from));
          setTimeout(
            () =>
              setTypingPeers((prev) => {
                const n = new Set(prev);
                n.delete(msg.from);
                return n;
              }),
            TYPING_TIMEOUT + 500,
          );
        } else {
          setTypingPeers((prev) => {
            const n = new Set(prev);
            n.delete(msg.from);
            return n;
          });
        }
      } else if (msg.type === "read") {
        setReadReceipts((prev) => ({ ...prev, [msg.msgId]: true }));
      } else if (msg.type === "error") {
        console.warn("server:", msg.error);
      }
    },
    [session, hasRatchetKeys, getRatchet, setRatchet, resolveDisplayName],
  );

  useEffect(() => {
    const encPub = session.keys?.encryption
      ? bs58.encode(session.keys.encryption.publicKey)
      : "";
    const ws = new WebSocket(
      `${WS_URL}?token=${session.token}&encPub=${encPub}`,
    );
    wsRef.current = ws;
    ws.onmessage = handleMsg;
    ws.onclose = () => console.log("ws closed");
    return () => ws.close();
  }, [session.token, handleMsg, session.keys]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  useEffect(() => {
    fetchDisplayName(session.token, session.pubkey).then((n) => {
      if (n) setMyName(n);
    });
  }, [session.token, session.pubkey]);

  function sendTyping() {
    const now = Date.now();
    if (!activePeer || now - lastTypingSentRef.current < TYPING_TIMEOUT) return;
    lastTypingSentRef.current = now;
    wsRef.current?.send(
      JSON.stringify({ type: "typing", to: activePeer, active: true }),
    );
    clearTimeout(typingTimerRef.current);
    typingTimerRef.current = setTimeout(() => {
      wsRef.current?.send(
        JSON.stringify({ type: "typing", to: activePeer, active: false }),
      );
    }, TYPING_TIMEOUT);
  }

  function send(e) {
    e.preventDefault();
    const text = input.trim();
    if (!text || wsRef.current?.readyState !== 1 || !activePeer) return;
    const state = getRatchet(activePeer);
    if (!state) {
      setMessages((prev) => [
        ...prev,
        {
          id: Date.now().toString(),
          from: "system",
          text: `no session with ${peerLabel(activePeer)} — click their name to init`,
          ts: Date.now(),
        },
      ]);
      setInput("");
      return;
    }
    const { header, nonce, ciphertext } = ratchetEncrypt(state, text);
    setRatchet(activePeer, state);
    const tempId = crypto.randomUUID();
    pendingRef.current.set(tempId, { text, peer: activePeer });
    wsRef.current.send(
      JSON.stringify({
        type: "chat",
        recipients: [{ to: activePeer, header, nonce, ciphertext }],
      }),
    );
    setTimeout(() => {
      if (pendingRef.current.has(tempId)) {
        const p = pendingRef.current.get(tempId);
        pendingRef.current.delete(tempId);
        setMessages((prev) => [
          ...prev,
          {
            id: tempId,
            from: session.pubkey,
            text: p.text,
            ts: Date.now(),
            peer: p.peer,
          },
        ]);
      }
    }, 3000);
    setInput("");
    wsRef.current.send(
      JSON.stringify({ type: "typing", to: activePeer, active: false }),
    );
  }

  async function handleSetName() {
    const name = nameInput.trim();
    if (!name) return;
    const result = await setDisplayName(session.token, name);
    if (result) {
      setMyName(result);
      setShowNameEdit(false);
      setNameInput("");
    }
  }

  function addContact() {
    const pk = addPeerInput.trim();
    if (!pk || pk === session.pubkey || contacts.includes(pk)) return;
    setContacts((prev) => [...prev, pk]);
    setAddPeerInput("");
    resolveDisplayName(pk);
  }

  const allPeers = [...new Set([...onlineUsers, ...contacts])];
  const peerMsgs = activePeer
    ? messages.filter(
        (m) =>
          m.from === activePeer ||
          (m.from === session.pubkey && m.peer === activePeer) ||
          m.from === "system",
      )
    : [];

  return (
    <div className="chat-layout">
      <aside className="sidebar">
        <div className="sidebar-header">
          <h2>torvex</h2>
          <div className="user-info">
            <span
              className="user-badge"
              title={session.pubkey}
              onClick={() => setShowNameEdit(!showNameEdit)}
            >
              {myName || shortKey(session.pubkey)}
            </span>
            {showNameEdit && (
              <div className="name-edit">
                <input
                  value={nameInput}
                  onChange={(e) => setNameInput(e.target.value)}
                  placeholder="display name"
                  maxLength={32}
                />
                <button onClick={handleSetName}>save</button>
              </div>
            )}
          </div>
        </div>
        <div className="add-contact">
          <input
            value={addPeerInput}
            onChange={(e) => setAddPeerInput(e.target.value)}
            placeholder="add by pubkey..."
          />
          <button onClick={addContact}>+</button>
        </div>
        <div className="online-list">
          <h3>peers</h3>
          {allPeers.length === 0 && <p className="muted">no contacts yet</p>}
          {allPeers.map((u) => (
            <div
              key={u}
              className={`online-user ${activePeer === u ? "active" : ""} ${onlineUsers.includes(u) ? "is-online" : "is-offline"}`}
              title={u}
              onClick={() => {
                setActivePeer(u);
                if (hasRatchetKeys && !getRatchet(u)) initSessionWithPeer(u);
                resolveDisplayName(u);
              }}
            >
              <span className="status-dot" />
              <span className="peer-name">{peerLabel(u)}</span>
              <span className="peer-lock">{getRatchet(u) ? "🔒" : "⚠️"}</span>
            </div>
          ))}
        </div>
        <button className="logout-btn" onClick={onLogout}>
          logout
        </button>
      </aside>
      <main className="chat-main">
        {!activePeer ? (
          <div className="empty-chat">
            <p>select a peer to start chatting</p>
          </div>
        ) : (
          <>
            <div className="chat-header">
              <h3>{peerLabel(activePeer)}</h3>
              <span
                className={`header-status ${onlineUsers.includes(activePeer) ? "online" : "offline"}`}
              >
                {onlineUsers.includes(activePeer) ? "online" : "offline"}
              </span>
              {typingPeers.has(activePeer) && (
                <span className="typing-indicator">typing...</span>
              )}
            </div>
            <div className="messages">
              {peerMsgs.length === 0 && (
                <div className="empty-chat">
                  <p>no messages yet. say something.</p>
                </div>
              )}
              {peerMsgs.map((m) => (
                <div
                  key={m.id}
                  className={`msg ${m.from === session.pubkey ? "msg-self" : m.from === "system" ? "msg-system" : "msg-other"}`}
                >
                  {m.from !== "system" && (
                    <span className="msg-author">
                      {m.from === session.pubkey
                        ? myName || "you"
                        : peerLabel(m.from)}
                    </span>
                  )}
                  <span className="msg-text">{m.text}</span>
                  <span className="msg-meta">
                    <span className="msg-time">
                      {new Date(m.ts).toLocaleTimeString()}
                    </span>
                    {m.from === session.pubkey && (
                      <span className="msg-check">
                        {readReceipts[m.id] ? "✓✓" : "✓"}
                      </span>
                    )}
                  </span>
                </div>
              ))}
              <div ref={bottomRef} />
            </div>
            <form className="chat-input" onSubmit={send}>
              <input
                value={input}
                onChange={(e) => {
                  setInput(e.target.value);
                  sendTyping();
                }}
                placeholder={`message ${peerLabel(activePeer)}...`}
                autoFocus
              />
              <button type="submit">send</button>
            </form>
          </>
        )}
      </main>
    </div>
  );
}
