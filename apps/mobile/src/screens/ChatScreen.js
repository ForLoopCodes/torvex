// torvex mobile - encrypted chat with double ratchet
// ws reconnect, offline decrypt, otp replenish, ratchet state

import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  FlatList,
  StyleSheet,
  KeyboardAvoidingView,
  Platform,
} from "react-native";
import bs58 from "bs58";
import {
  generateEphemeralKey,
  generateOneTimePrekeys,
  x3dhInitiator,
  x3dhResponder,
} from "../crypto/x3dh";
import {
  initSender,
  initReceiver,
  ratchetEncrypt,
  ratchetDecrypt,
  serializeState,
  deserializeState,
} from "../crypto/ratchet";
import {
  fetchPrekeyBundle,
  fetchPendingMessages,
  fetchDisplayName,
  setDisplayName,
  checkAndReplenishOtps,
} from "../utils/api";
import { storage } from "../utils/storage";

const WS_URL = "ws://10.0.2.2:4400";
const RATCHET_PREFIX = "torvex_ratchet_";
const HISTORY_PREFIX = "torvex_hist_";
const MAX_HISTORY = 200;
const RECONNECT_BASE = 1000;
const RECONNECT_MAX = 30000;

function shortKey(pk) {
  return pk.slice(0, 4) + "..." + pk.slice(-4);
}

function loadRatchetState(myPk, peerPk) {
  try {
    const raw = storage.getItem(`${RATCHET_PREFIX}${myPk}:${peerPk}`);
    return raw ? deserializeState(raw) : null;
  } catch {
    return null;
  }
}

function saveRatchetState(myPk, peerPk, state) {
  try {
    storage.setItem(
      `${RATCHET_PREFIX}${myPk}:${peerPk}`,
      serializeState(state),
    );
  } catch {}
}

function loadHistory(myPk, peerPk) {
  try {
    return JSON.parse(
      storage.getItem(`${HISTORY_PREFIX}${myPk}:${peerPk}`) || "[]",
    );
  } catch {
    return [];
  }
}

function saveHistory(myPk, peerPk, msgs) {
  try {
    storage.setItem(
      `${HISTORY_PREFIX}${myPk}:${peerPk}`,
      JSON.stringify(msgs.slice(-MAX_HISTORY)),
    );
  } catch {}
}

export default function ChatScreen({ session, scannedPk, onScan, onLogout }) {
  const [messages, setMessages] = useState({});
  const [input, setInput] = useState("");
  const [onlineUsers, setOnlineUsers] = useState([]);
  const [activePeer, setActivePeer] = useState(null);
  const [peerNames, setPeerNames] = useState({});
  const [addPeerInput, setAddPeerInput] = useState("");
  const [unread, setUnread] = useState({});
  const [wsStatus, setWsStatus] = useState("connecting");
  const [showSidebar, setShowSidebar] = useState(true);
  const [contacts, setContacts] = useState(() => {
    try {
      return JSON.parse(
        storage.getItem(`torvex_contacts_${session.pubkey}`) || "[]",
      );
    } catch {
      return [];
    }
  });

  const wsRef = useRef(null);
  const flatListRef = useRef(null);
  const ratchetsRef = useRef(new Map());
  const pendingRef = useRef(new Map());
  const initializingRef = useRef(new Set());
  const reconnectRef = useRef(0);
  const reconnectTimerRef = useRef(null);
  const activePeerRef = useRef(null);

  const hasRatchetKeys = !!session.keys?.identity && !!session.keys?.encryption;

  useEffect(() => {
    activePeerRef.current = activePeer;
  }, [activePeer]);

  useEffect(() => {
    storage.setItem(
      `torvex_contacts_${session.pubkey}`,
      JSON.stringify(contacts),
    );
  }, [contacts, session.pubkey]);

  useEffect(() => {
    if (
      scannedPk &&
      scannedPk !== session.pubkey &&
      !contacts.includes(scannedPk)
    ) {
      setContacts((prev) => [...prev, scannedPk]);
      selectPeer(scannedPk);
    }
  }, [scannedPk]);

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
          text: `ratchet session started`,
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
        const state = getRatchet(pm.fromPubkey);
        if (!state) continue;
        const text = ratchetDecrypt(
          state,
          data.header,
          data.nonce,
          data.ciphertext,
        );
        setRatchet(pm.fromPubkey, state);
        addMsg(pm.fromPubkey, {
          id: pm.id,
          from: pm.fromPubkey,
          text,
          ts: new Date(pm.createdAt).getTime(),
        });
        if (activePeerRef.current !== pm.fromPubkey)
          setUnread((prev) => ({
            ...prev,
            [pm.fromPubkey]: (prev[pm.fromPubkey] || 0) + 1,
          }));
      } catch {}
    }
  }, [session.token, hasRatchetKeys, getRatchet, setRatchet, addMsg]);

  const handleMsg = useCallback(
    (e) => {
      const msg = JSON.parse(e.data);

      if (msg.type === "user_joined") {
        setOnlineUsers((prev) => [...new Set([...prev, msg.pubkey])]);
        resolveDisplayName(msg.pubkey);
      } else if (msg.type === "user_left") {
        setOnlineUsers((prev) => prev.filter((u) => u !== msg.pubkey));
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
            text: `session established with ${shortKey(msg.from)}`,
            ts: Date.now(),
          });
        } catch {}
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
        addMsg(msg.from, { id: msg.id, from: msg.from, text, ts: msg.ts });
        if (activePeerRef.current !== msg.from)
          setUnread((prev) => ({
            ...prev,
            [msg.from]: (prev[msg.from] || 0) + 1,
          }));
      } else if (msg.type === "chat_ack") {
        const pending = pendingRef.current.get(msg.id);
        if (pending) {
          pendingRef.current.delete(msg.id);
          addMsg(pending.peer, {
            id: msg.id,
            from: session.pubkey,
            text: pending.text,
            ts: msg.ts,
          });
        }
      }
    },
    [
      session,
      hasRatchetKeys,
      getRatchet,
      setRatchet,
      resolveDisplayName,
      addMsg,
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

  function send() {
    const text = input.trim();
    if (!text || wsRef.current?.readyState !== 1 || !activePeer) return;
    const state = getRatchet(activePeer);
    if (!state) {
      addMsg(activePeer, {
        id: Date.now().toString(),
        from: "system",
        text: "no session — tap peer to init",
        ts: Date.now(),
      });
      setInput("");
      return;
    }
    const { header, nonce, ciphertext } = ratchetEncrypt(state, text);
    setRatchet(activePeer, state);
    const tempId = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
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
        });
      }
    }, 3000);
    setInput("");
  }

  function addContact() {
    const pk = addPeerInput.trim();
    if (!pk || pk === session.pubkey || contacts.includes(pk)) return;
    setContacts((prev) => [...prev, pk]);
    setAddPeerInput("");
    resolveDisplayName(pk);
  }

  function selectPeer(pk) {
    setActivePeer(pk);
    setUnread((prev) => ({ ...prev, [pk]: 0 }));
    setShowSidebar(false);
    if (hasRatchetKeys && !getRatchet(pk)) initSessionWithPeer(pk);
    resolveDisplayName(pk);
  }

  const allPeers = [...new Set([...onlineUsers, ...contacts])].filter(
    (u) => u !== session.pubkey,
  );
  const peerMsgs = activePeer ? messages[activePeer] || [] : [];

  const renderMsg = ({ item: m }) => (
    <View
      style={[
        s.msgBubble,
        m.from === session.pubkey
          ? s.msgSelf
          : m.from === "system"
          ? s.msgSystem
          : s.msgOther,
      ]}
    >
      {m.from !== "system" && (
        <Text style={s.msgAuthor}>
          {m.from === session.pubkey ? "you" : peerLabel(m.from)}
        </Text>
      )}
      <Text style={m.from === "system" ? s.msgSystemText : s.msgText}>
        {m.text}
      </Text>
      <Text style={s.msgTime}>{new Date(m.ts).toLocaleTimeString()}</Text>
    </View>
  );

  if (showSidebar || !activePeer) {
    return (
      <View style={s.container}>
        <View style={s.header}>
          <Text style={s.headerTitle}>torvex</Text>
          <View style={s.statusRow}>
            <View
              style={[s.dot, wsStatus === "connected" ? s.dotOk : s.dotErr]}
            />
            <Text style={s.statusText}>{wsStatus}</Text>
          </View>
        </View>
        <View style={s.addRow}>
          <TextInput
            style={[s.input, { flex: 1 }]}
            value={addPeerInput}
            onChangeText={setAddPeerInput}
            placeholder="add by pubkey..."
            placeholderTextColor="#6b6b80"
            autoCapitalize="none"
          />
          <TouchableOpacity style={s.addBtn} onPress={addContact}>
            <Text style={s.addBtnText}>+</Text>
          </TouchableOpacity>
          <TouchableOpacity style={s.addBtn} onPress={onScan}>
            <Text style={s.addBtnText}>📷</Text>
          </TouchableOpacity>
        </View>
        <FlatList
          data={allPeers}
          keyExtractor={(pk) => pk}
          renderItem={({ item: pk }) => (
            <TouchableOpacity style={s.peerRow} onPress={() => selectPeer(pk)}>
              <View
                style={[s.dot, onlineUsers.includes(pk) ? s.dotOk : s.dotErr]}
              />
              <Text style={s.peerName} numberOfLines={1}>
                {peerLabel(pk)}
              </Text>
              {(unread[pk] || 0) > 0 && (
                <View style={s.badge}>
                  <Text style={s.badgeText}>{unread[pk]}</Text>
                </View>
              )}
              <Text style={s.lockIcon}>{getRatchet(pk) ? "🔒" : "⚠️"}</Text>
            </TouchableOpacity>
          )}
          ListEmptyComponent={<Text style={s.muted}>no contacts yet</Text>}
        />
        <TouchableOpacity style={s.logoutBtn} onPress={onLogout}>
          <Text style={s.logoutText}>logout</Text>
        </TouchableOpacity>
      </View>
    );
  }

  return (
    <KeyboardAvoidingView
      style={s.container}
      behavior={Platform.OS === "ios" ? "padding" : undefined}
    >
      <View style={s.chatHeader}>
        <TouchableOpacity onPress={() => setShowSidebar(true)}>
          <Text style={s.backBtn}>←</Text>
        </TouchableOpacity>
        <Text style={s.chatHeaderTitle} numberOfLines={1}>
          {peerLabel(activePeer)}
        </Text>
        <Text
          style={[
            s.statusText,
            onlineUsers.includes(activePeer) ? s.onlineText : {},
          ]}
        >
          {onlineUsers.includes(activePeer) ? "online" : "offline"}
        </Text>
      </View>
      <FlatList
        ref={flatListRef}
        data={peerMsgs}
        keyExtractor={(m) => m.id}
        renderItem={renderMsg}
        onContentSizeChange={() =>
          flatListRef.current?.scrollToEnd({ animated: true })
        }
        contentContainerStyle={s.msgList}
        ListEmptyComponent={<Text style={s.muted}>no messages yet</Text>}
      />
      <View style={s.inputRow}>
        <TextInput
          style={[s.input, { flex: 1 }]}
          value={input}
          onChangeText={setInput}
          placeholder={`message ${peerLabel(activePeer)}...`}
          placeholderTextColor="#6b6b80"
          editable={wsStatus === "connected"}
          onSubmitEditing={send}
          returnKeyType="send"
        />
        <TouchableOpacity
          style={[s.sendBtn, wsStatus !== "connected" && s.disabled]}
          onPress={send}
          disabled={wsStatus !== "connected"}
        >
          <Text style={s.sendBtnText}>→</Text>
        </TouchableOpacity>
      </View>
    </KeyboardAvoidingView>
  );
}

const s = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#0a0a0f" },
  header: {
    paddingTop: 48,
    paddingHorizontal: 16,
    paddingBottom: 12,
    backgroundColor: "#12121a",
    borderBottomWidth: 1,
    borderBottomColor: "#1e1e2e",
  },
  headerTitle: {
    fontSize: 24,
    fontWeight: "800",
    color: "#7c5cfc",
    letterSpacing: 2,
  },
  statusRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: 6,
    marginTop: 4,
  },
  dot: { width: 8, height: 8, borderRadius: 4 },
  dotOk: { backgroundColor: "#4ade80" },
  dotErr: { backgroundColor: "#e05555" },
  statusText: { color: "#6b6b80", fontSize: 12 },
  onlineText: { color: "#4ade80" },
  addRow: {
    flexDirection: "row",
    padding: 12,
    gap: 8,
    borderBottomWidth: 1,
    borderBottomColor: "#1e1e2e",
  },
  input: {
    backgroundColor: "#12121a",
    borderWidth: 1,
    borderColor: "#1e1e2e",
    color: "#e4e4ef",
    padding: 12,
    borderRadius: 8,
    fontSize: 14,
  },
  addBtn: {
    backgroundColor: "#7c5cfc",
    paddingHorizontal: 16,
    borderRadius: 8,
    justifyContent: "center",
  },
  addBtnText: { color: "#fff", fontSize: 20, fontWeight: "700" },
  peerRow: {
    flexDirection: "row",
    alignItems: "center",
    padding: 14,
    paddingHorizontal: 16,
    borderBottomWidth: 1,
    borderBottomColor: "#1e1e2e",
    gap: 10,
  },
  peerName: { color: "#e4e4ef", fontSize: 15, flex: 1 },
  badge: {
    backgroundColor: "#7c5cfc",
    borderRadius: 10,
    paddingHorizontal: 7,
    paddingVertical: 2,
  },
  badgeText: { color: "#fff", fontSize: 11, fontWeight: "700" },
  lockIcon: { fontSize: 14 },
  muted: { color: "#6b6b80", textAlign: "center", padding: 24 },
  logoutBtn: {
    padding: 16,
    borderTopWidth: 1,
    borderTopColor: "#1e1e2e",
    alignItems: "center",
  },
  logoutText: { color: "#e05555", fontWeight: "600" },
  chatHeader: {
    flexDirection: "row",
    alignItems: "center",
    paddingTop: 48,
    paddingHorizontal: 16,
    paddingBottom: 12,
    backgroundColor: "#12121a",
    borderBottomWidth: 1,
    borderBottomColor: "#1e1e2e",
    gap: 12,
  },
  backBtn: { color: "#7c5cfc", fontSize: 24, fontWeight: "700" },
  chatHeaderTitle: {
    color: "#e4e4ef",
    fontSize: 18,
    fontWeight: "700",
    flex: 1,
  },
  msgList: { padding: 12, paddingBottom: 8 },
  msgBubble: {
    maxWidth: "80%",
    padding: 10,
    borderRadius: 12,
    marginBottom: 8,
  },
  msgSelf: {
    backgroundColor: "#1a1a2e",
    alignSelf: "flex-end",
    borderBottomRightRadius: 4,
  },
  msgOther: {
    backgroundColor: "#161622",
    alignSelf: "flex-start",
    borderBottomLeftRadius: 4,
  },
  msgSystem: { alignSelf: "center", backgroundColor: "transparent" },
  msgAuthor: {
    color: "#7c5cfc",
    fontSize: 11,
    fontWeight: "600",
    marginBottom: 2,
  },
  msgText: { color: "#e4e4ef", fontSize: 15 },
  msgSystemText: {
    color: "#6b6b80",
    fontSize: 12,
    fontStyle: "italic",
    textAlign: "center",
  },
  msgTime: { color: "#6b6b80", fontSize: 10, marginTop: 4, textAlign: "right" },
  inputRow: {
    flexDirection: "row",
    padding: 12,
    gap: 8,
    borderTopWidth: 1,
    borderTopColor: "#1e1e2e",
    backgroundColor: "#12121a",
  },
  sendBtn: {
    backgroundColor: "#7c5cfc",
    paddingHorizontal: 18,
    borderRadius: 8,
    justifyContent: "center",
  },
  sendBtnText: { color: "#fff", fontSize: 20, fontWeight: "700" },
  disabled: { opacity: 0.5 },
});
