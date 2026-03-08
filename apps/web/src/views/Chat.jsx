// torvex web - encrypted chat with signal double ratchet
// reconnect, notifications, otp replenish, message persistence

import React, { useState, useEffect, useRef, useCallback } from "react";
import bs58 from "bs58";
import {
  generateEphemeralKey,
  generateOneTimePrekeys,
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
const RATCHET_PREFIX = "torvex_ratchet_";
const HISTORY_PREFIX = "torvex_hist_";
const TYPING_TIMEOUT = 2000;
const RECONNECT_BASE = 1000;
const RECONNECT_MAX = 30000;
const MAX_HISTORY = 200;
const OTP_LOW_THRESHOLD = 5;
const OTP_REPLENISH_COUNT = 10;

function shortKey(pk) {
  return pk.slice(0, 4) + "..." + pk.slice(-4);
}

function loadRatchetState(myPk, peerPk) {
  try {
    const raw = sessionStorage.getItem(`${RATCHET_PREFIX}${myPk}:${peerPk}`);
    return raw ? deserializeState(raw) : null;
  } catch {
    return null;
  }
}

function saveRatchetState(myPk, peerPk, state) {
  try {
    sessionStorage.setItem(
      `${RATCHET_PREFIX}${myPk}:${peerPk}`,
      serializeState(state),
    );
  } catch {}
}

function loadHistory(myPk, peerPk) {
  try {
    return JSON.parse(
      localStorage.getItem(`${HISTORY_PREFIX}${myPk}:${peerPk}`) || "[]",
    );
  } catch {
    return [];
  }
}

function saveHistory(myPk, peerPk, msgs) {
  try {
    localStorage.setItem(
      `${HISTORY_PREFIX}${myPk}:${peerPk}`,
      JSON.stringify(msgs.slice(-MAX_HISTORY)),
    );
  } catch {}
}

function notifyMsg(from, text) {
  if (
    document.hidden &&
    Notification.permission === "granted" &&
    text.length > 0
  ) {
    new Notification(`torvex — ${from}`, {
      body: text.slice(0, 100),
      icon: "/favicon.ico",
    });
  }
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

async function setMyDisplayName(token, name) {
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

async function checkAndReplenishOtps(token) {
  try {
    const countRes = await fetch(`${API}/keys/count`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!countRes.ok) return;
    const { count } = await countRes.json();
    if (count >= OTP_LOW_THRESHOLD) return;
    const otps = generateOneTimePrekeys(OTP_REPLENISH_COUNT);
    await fetch(`${API}/keys/replenish`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        oneTimePrekeys: otps.map((k) => ({
          id: k.id,
          publicKey: bs58.encode(k.keyPair.publicKey),
        })),
      }),
    });
  } catch {}
}

export default function Chat({ session, onLogout }) {
  const [messages, setMessages] = useState({});
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
  const [unread, setUnread] = useState({});
  const [wsStatus, setWsStatus] = useState("connecting");
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
  const reconnectRef = useRef(0);
  const reconnectTimerRef = useRef(null);
  const activePeerRef = useRef(null);

  const hasRatchetKeys = !!session.keys?.identity && !!session.keys?.encryption;

  useEffect(() => {
    activePeerRef.current = activePeer;
  }, [activePeer]);

  useEffect(() => {
    localStorage.setItem(
      `torvex_contacts_${session.pubkey}`,
      JSON.stringify(contacts),
    );
  }, [contacts, session.pubkey]);

  useEffect(() => {
    if (Notification.permission === "default") Notification.requestPermission();
  }, []);

  const addMsg = useCallback(
    (peerPk, msg) => {
      setMessages((prev) => {
        const list = [...(prev[peerPk] || []), msg].slice(-MAX_HISTORY);
        saveHistory(session.pubkey, peerPk, list);
        return { ...prev, [peerPk]: list };
      });
    },
    [session.pubkey],
  );

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
          addMsg(peerPk, {
            id: Date.now().toString(),
            from: "system",
            text: `${peerLabel(peerPk)} has no prekey bundle`,
            ts: Date.now(),
          });
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
        addMsg(peerPk, {
          id: Date.now().toString(),
          from: "system",
          text: `ratchet session started with ${peerLabel(peerPk)}`,
          ts: Date.now(),
        });
      } catch (err) {
        addMsg(peerPk, {
          id: Date.now().toString(),
          from: "system",
          text: `session setup failed: ${err.message}`,
          ts: Date.now(),
        });
      } finally {
        initializingRef.current.delete(peerPk);
      }
    },
    [session, hasRatchetKeys, getRatchet, setRatchet, peerLabel, addMsg],
  );

  const processOfflineMessages = useCallback(async () => {
    if (!hasRatchetKeys) return;
    const pending = await fetchPendingMessages(session.token);
    for (const pm of pending) {
      try {
        const data = JSON.parse(pm.ciphertext);
        if (!data.header || !data.nonce || !data.ciphertext) continue;
        const senderPk = pm.fromPubkey;
        const state = getRatchet(senderPk);
        if (!state) continue;
        const text = ratchetDecrypt(
          state,
          data.header,
          data.nonce,
          data.ciphertext,
        );
        setRatchet(senderPk, state);
        addMsg(senderPk, {
          id: pm.id,
          from: senderPk,
          text,
          ts: new Date(pm.createdAt).getTime(),
          read: false,
        });
        if (activePeerRef.current !== senderPk)
          setUnread((prev) => ({
            ...prev,
            [senderPk]: (prev[senderPk] || 0) + 1,
          }));
        notifyMsg(peerLabel(senderPk), text);
      } catch {}
    }
  }, [
    session.token,
    hasRatchetKeys,
    getRatchet,
    setRatchet,
    addMsg,
    peerLabel,
  ]);

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
          if (!contacts.includes(msg.from))
            setContacts((prev) => [...prev, msg.from]);
          addMsg(msg.from, {
            id: Date.now().toString(),
            from: "system",
            text: `ratchet session established with ${shortKey(msg.from)}`,
            ts: Date.now(),
          });
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
        addMsg(msg.from, {
          id: msg.id,
          from: msg.from,
          text,
          ts: msg.ts,
          read: false,
        });
        if (activePeerRef.current !== msg.from)
          setUnread((prev) => ({
            ...prev,
            [msg.from]: (prev[msg.from] || 0) + 1,
          }));
        notifyMsg(peerLabel(msg.from), text);
        if (wsRef.current?.readyState === 1)
          wsRef.current.send(
            JSON.stringify({ type: "read", to: msg.from, msgId: msg.id }),
          );
      } else if (msg.type === "chat_ack") {
        const pending = pendingRef.current.get(msg.id);
        if (pending) {
          pendingRef.current.delete(msg.id);
          addMsg(pending.peer, {
            id: msg.id,
            from: session.pubkey,
            text: pending.text,
            ts: msg.ts,
            peer: pending.peer,
            read: false,
          });
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
      }
    },
    [
      session,
      hasRatchetKeys,
      getRatchet,
      setRatchet,
      resolveDisplayName,
      addMsg,
      peerLabel,
      contacts,
    ],
  );

  const connectWs = useCallback(() => {
    const encPub = session.keys?.encryption
      ? bs58.encode(session.keys.encryption.publicKey)
      : "";
    const ws = new WebSocket(
      `${WS_URL}?token=${session.token}&encPub=${encPub}`,
    );
    wsRef.current = ws;
    setWsStatus("connecting");

    ws.onopen = () => {
      setWsStatus("connected");
      reconnectRef.current = 0;
      processOfflineMessages();
      checkAndReplenishOtps(session.token);
    };

    ws.onmessage = handleMsg;

    ws.onclose = (ev) => {
      setWsStatus("disconnected");
      if (ev.code === 4001 || ev.code === 4002) return;
      const delay = Math.min(
        RECONNECT_BASE * 2 ** reconnectRef.current,
        RECONNECT_MAX,
      );
      reconnectRef.current++;
      reconnectTimerRef.current = setTimeout(connectWs, delay);
    };

    ws.onerror = () => ws.close();

    return ws;
  }, [session, handleMsg, processOfflineMessages]);

  useEffect(() => {
    const ws = connectWs();
    return () => {
      clearTimeout(reconnectTimerRef.current);
      ws.close();
    };
  }, [connectWs]);

  useEffect(() => {
    const loaded = {};
    contacts.forEach((pk) => {
      const hist = loadHistory(session.pubkey, pk);
      if (hist.length) loaded[pk] = hist;
    });
    if (Object.keys(loaded).length)
      setMessages((prev) => ({ ...loaded, ...prev }));
  }, [session.pubkey, contacts]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, activePeer]);

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
      addMsg(activePeer, {
        id: Date.now().toString(),
        from: "system",
        text: `no session with ${peerLabel(activePeer)} — click their name to init`,
        ts: Date.now(),
      });
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
        addMsg(p.peer, {
          id: tempId,
          from: session.pubkey,
          text: p.text,
          ts: Date.now(),
          peer: p.peer,
        });
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
    const result = await setMyDisplayName(session.token, name);
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

  function copyPubkey() {
    navigator.clipboard?.writeText(session.pubkey);
  }

  function selectPeer(pk) {
    setActivePeer(pk);
    setUnread((prev) => ({ ...prev, [pk]: 0 }));
    if (hasRatchetKeys && !getRatchet(pk)) initSessionWithPeer(pk);
    resolveDisplayName(pk);
  }

  const allPeers = [...new Set([...onlineUsers, ...contacts])].filter(
    (u) => u !== session.pubkey,
  );
  const peerMsgs = activePeer ? messages[activePeer] || [] : [];

  return (
    <div className="chat-layout">
      <aside className="sidebar">
        <div className="sidebar-header">
          <h2>torvex</h2>
          <div className="user-info">
            <span
              className="user-badge"
              title={`click to edit name\n${session.pubkey}`}
              onClick={() => setShowNameEdit(!showNameEdit)}
            >
              {myName || shortKey(session.pubkey)}
            </span>
            <span className="copy-pk" title="copy pubkey" onClick={copyPubkey}>
              copy id
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
        <div className="ws-status">
          <span
            className={`status-dot ${wsStatus === "connected" ? "dot-ok" : wsStatus === "connecting" ? "dot-warn" : "dot-err"}`}
          />
          <span className="ws-label">{wsStatus}</span>
        </div>
        <div className="add-contact">
          <input
            value={addPeerInput}
            onChange={(e) => setAddPeerInput(e.target.value)}
            placeholder="add by pubkey..."
            onKeyDown={(e) => e.key === "Enter" && addContact()}
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
              onClick={() => selectPeer(u)}
            >
              <span className="status-dot" />
              <span className="peer-name">{peerLabel(u)}</span>
              {(unread[u] || 0) > 0 && (
                <span className="unread-badge">{unread[u]}</span>
              )}
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
                disabled={wsStatus !== "connected"}
              />
              <button type="submit" disabled={wsStatus !== "connected"}>
                send
              </button>
            </form>
          </>
        )}
      </main>
    </div>
  );
}
