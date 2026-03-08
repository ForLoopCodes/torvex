// torvex web - self-contained bip39 wallet auth
// pin-encrypted key storage, device id, prekey upload

import React, { useState, useEffect } from "react";
import nacl from "tweetnacl";
import bs58 from "bs58";
import {
  deriveAllKeys,
  pubkeyB58,
  generateMnemonic,
  validateMnemonic,
} from "../crypto/keys.js";
import {
  generateSignedPrekey,
  generateOneTimePrekeys,
  createPrekeyBundle,
} from "../crypto/x3dh.js";

const API = import.meta.env.VITE_API_URL || "http://localhost:4400";
const VAULT_KEY = "torvex_vault";
const DEVICE_KEY = "torvex_device_id";

function getDeviceId() {
  let id = localStorage.getItem(DEVICE_KEY);
  if (!id) {
    id = crypto.randomUUID();
    localStorage.setItem(DEVICE_KEY, id);
  }
  return id;
}

async function deriveEncKey(pin) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(pin),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: enc.encode("torvex-vault-v1"), iterations: 300000, hash: "SHA-256" },
    key,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptVault(pin, mnemonic) {
  const key = await deriveEncKey(pin);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(mnemonic),
  );
  const data = { iv: bs58.encode(iv), ct: bs58.encode(new Uint8Array(ct)) };
  localStorage.setItem(VAULT_KEY, JSON.stringify(data));
}

async function decryptVault(pin) {
  const raw = localStorage.getItem(VAULT_KEY);
  if (!raw) return null;
  const { iv, ct } = JSON.parse(raw);
  const key = await deriveEncKey(pin);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: bs58.decode(iv) },
    key,
    bs58.decode(ct),
  );
  return new TextDecoder().decode(plain);
}

async function fetchChallenge(pubkey) {
  const res = await fetch(`${API}/auth/challenge`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pubkey }),
  });
  const data = await res.json();
  if (!data.challenge) throw new Error("failed to get challenge");
  return data.challenge;
}

async function verifySignature(pubkey, signature, deviceId) {
  const res = await fetch(`${API}/auth/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pubkey, signature, deviceId }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error);
  return data;
}

async function uploadPrekeyBundle(token, bundle, deviceId) {
  await fetch(`${API}/keys/bundle`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      deviceId,
      identityKey: bs58.encode(bundle.identityKey),
      signedPrekey: bs58.encode(bundle.signedPrekey),
      signedPrekeySig: bs58.encode(bundle.signedPrekeySignature),
      oneTimePrekeys: bundle.oneTimePrekeys.map((k) => ({
        id: k.id,
        publicKey: bs58.encode(k.publicKey),
      })),
    }),
  });
}

export default function Auth({ onAuth }) {
  const [mnemonic, setMnemonic] = useState("");
  const [pin, setPin] = useState("");
  const [phase, setPhase] = useState("start");
  const [error, setError] = useState("");
  const [generatedPhrase, setGeneratedPhrase] = useState("");
  const [hasVault, setHasVault] = useState(false);

  useEffect(() => {
    setHasVault(!!localStorage.getItem(VAULT_KEY));
  }, []);

  async function authenticate(phrase, userPin) {
    setError("");
    try {
      const deviceId = getDeviceId();
      const keys = deriveAllKeys(phrase);
      const pubkey = pubkeyB58(keys.identity);
      const challenge = await fetchChallenge(pubkey);
      const signature = bs58.encode(
        nacl.sign.detached(
          new TextEncoder().encode(challenge),
          keys.identity.secretKey,
        ),
      );
      const data = await verifySignature(pubkey, signature, deviceId);

      const signedPre = generateSignedPrekey(keys.identity.secretKey);
      const otps = generateOneTimePrekeys(10);
      const bundle = createPrekeyBundle(keys.identity, signedPre, otps);
      await uploadPrekeyBundle(data.token, bundle, deviceId);

      await encryptVault(userPin, phrase);

      onAuth({
        token: data.token,
        pubkey: data.pubkey,
        deviceId,
        keys,
        signedPrekey: signedPre,
        oneTimePrekeys: otps,
      });
    } catch (err) {
      setError(err.message);
    }
  }

  async function unlockVault() {
    setError("");
    if (!pin || pin.length < 4) return setError("pin must be at least 4 digits");
    try {
      const phrase = await decryptVault(pin);
      if (!phrase) return setError("no saved wallet found");
      await authenticate(phrase, pin);
    } catch {
      setError("wrong pin or corrupted vault");
    }
  }

  function clearVault() {
    localStorage.removeItem(VAULT_KEY);
    setHasVault(false);
    setPhase("start");
  }

  if (hasVault && phase === "start") {
    return (
      <div className="auth-wrap">
        <div className="auth-card">
          <h1 className="logo">torvex</h1>
          <p className="tagline">enter your pin to unlock</p>
          <input
            type="password"
            value={pin}
            onChange={(e) => setPin(e.target.value.replace(/\D/g, ""))}
            placeholder="pin code"
            maxLength={8}
            onKeyDown={(e) => e.key === "Enter" && unlockVault()}
          />
          {error && <p className="error">{error}</p>}
          <button onClick={unlockVault}>unlock</button>
          <p className="switch" onClick={clearVault}>
            use different wallet
          </p>
        </div>
      </div>
    );
  }

  if (phase === "generated") {
    return (
      <div className="auth-wrap">
        <div className="auth-card">
          <h1 className="logo">torvex</h1>
          <p className="tagline">your new wallet seed phrase</p>
          <div className="seed-display">
            {generatedPhrase.split(" ").map((word, i) => (
              <span key={i} className="seed-word">
                <em>{i + 1}.</em> {word}
              </span>
            ))}
          </div>
          <p className="warning">
            write this down. it is your only login. lose it and you lose access
            forever.
          </p>
          <p className="tagline">set a pin to encrypt your keys locally</p>
          <input
            type="password"
            value={pin}
            onChange={(e) => setPin(e.target.value.replace(/\D/g, ""))}
            placeholder="pin code (4+ digits)"
            maxLength={8}
          />
          {error && <p className="error">{error}</p>}
          <button
            onClick={() => {
              if (pin.length < 4) return setError("pin must be at least 4 digits");
              authenticate(generatedPhrase, pin);
            }}
          >
            i saved it — sign in
          </button>
          <p className="switch" onClick={() => setPhase("start")}>
            back
          </p>
        </div>
      </div>
    );
  }

  if (phase === "restore") {
    return (
      <div className="auth-wrap">
        <div className="auth-card">
          <h1 className="logo">torvex</h1>
          <p className="tagline">enter your 24-word seed phrase</p>
          <textarea
            className="seed-input"
            rows={4}
            placeholder="word1 word2 word3 ... word24"
            value={mnemonic}
            onChange={(e) => setMnemonic(e.target.value.toLowerCase())}
          />
          <p className="tagline">set a pin to encrypt your keys locally</p>
          <input
            type="password"
            value={pin}
            onChange={(e) => setPin(e.target.value.replace(/\D/g, ""))}
            placeholder="pin code (4+ digits)"
            maxLength={8}
          />
          {error && <p className="error">{error}</p>}
          <button
            onClick={() => {
              if (!validateMnemonic(mnemonic.trim()))
                return setError("invalid seed phrase");
              if (pin.length < 4) return setError("pin must be at least 4 digits");
              authenticate(mnemonic.trim(), pin);
            }}
          >
            sign in with seed
          </button>
          <p className="switch" onClick={() => setPhase("start")}>
            back
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="auth-wrap">
      <div className="auth-card">
        <h1 className="logo">torvex</h1>
        <p className="tagline">encrypted. anonymous. yours.</p>
        <div className="auth-section">
          <button
            onClick={() => {
              setGeneratedPhrase(generateMnemonic());
              setPhase("generated");
            }}
          >
            create new wallet
          </button>
          <button className="btn-secondary" onClick={() => setPhase("restore")}>
            restore from seed phrase
          </button>
        </div>
        {error && <p className="error">{error}</p>}
      </div>
    </div>
  );
}
