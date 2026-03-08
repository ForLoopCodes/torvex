// torvex web - wallet auth with bip44 hd derivation
// phantom, metamask, and seed phrase login with prekey upload

import React, { useState } from "react";
import * as bip39 from "bip39";
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

async function verifySignature(pubkey, signature) {
  const res = await fetch(`${API}/auth/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pubkey, signature }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error);
  return data;
}

async function uploadPrekeyBundle(token, bundle) {
  await fetch(`${API}/keys/bundle`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
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
  const [phase, setPhase] = useState("start");
  const [error, setError] = useState("");
  const [generatedPhrase, setGeneratedPhrase] = useState("");
  const [loading, setLoading] = useState("");

  async function signInWithSeed(phrase) {
    setError("");
    try {
      const keys = deriveAllKeys(phrase);
      const pubkey = pubkeyB58(keys.identity);
      const challenge = await fetchChallenge(pubkey);
      const signature = bs58.encode(
        nacl.sign.detached(
          new TextEncoder().encode(challenge),
          keys.identity.secretKey,
        ),
      );
      const data = await verifySignature(pubkey, signature);

      const signedPre = generateSignedPrekey(keys.identity.secretKey);
      const otps = generateOneTimePrekeys(10);
      const bundle = createPrekeyBundle(keys.identity, signedPre, otps);
      await uploadPrekeyBundle(data.token, bundle);

      onAuth({
        token: data.token,
        pubkey: data.pubkey,
        mnemonic: phrase,
        keys,
        signedPrekey: signedPre,
        oneTimePrekeys: otps,
      });
    } catch (err) {
      setError(err.message);
    }
  }

  async function signInWithPhantom() {
    setError("");
    setLoading("phantom");
    try {
      const phantom = window?.solana;
      if (!phantom?.isPhantom)
        throw new Error(
          "phantom wallet not found — install it from phantom.app",
        );
      const resp = await phantom.connect();
      const pubkey = resp.publicKey.toString();
      const challenge = await fetchChallenge(pubkey);
      const { signature } = await phantom.signMessage(
        new TextEncoder().encode(challenge),
        "utf8",
      );
      const data = await verifySignature(pubkey, bs58.encode(signature));
      const ephEncrypt = nacl.box.keyPair();
      onAuth({
        token: data.token,
        pubkey: data.pubkey,
        mnemonic: null,
        keys: { identity: null, encryption: ephEncrypt, prekey: null },
        signedPrekey: null,
        oneTimePrekeys: null,
      });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading("");
    }
  }

  async function signInWithMetaMask() {
    setError("");
    setLoading("metamask");
    try {
      if (!window?.ethereum?.isMetaMask)
        throw new Error("metamask not found — install it from metamask.io");
      const accounts = await window.ethereum.request({
        method: "eth_requestAccounts",
      });
      const address = accounts[0];
      const challenge = await fetchChallenge(address);
      const signature = await window.ethereum.request({
        method: "personal_sign",
        params: [challenge, address],
      });
      const data = await verifySignature(address, signature);
      const ephEncrypt = nacl.box.keyPair();
      onAuth({
        token: data.token,
        pubkey: data.pubkey,
        mnemonic: null,
        keys: { identity: null, encryption: ephEncrypt, prekey: null },
        signedPrekey: null,
        oneTimePrekeys: null,
      });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading("");
    }
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
          <button onClick={() => signInWithSeed(generatedPhrase)}>
            i saved it — sign in
          </button>
          {error && <p className="error">{error}</p>}
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
          {error && <p className="error">{error}</p>}
          <button
            onClick={() => {
              if (!validateMnemonic(mnemonic.trim()))
                return setError("invalid seed phrase");
              signInWithSeed(mnemonic.trim());
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
          <h3 className="section-label">wallet extensions</h3>
          <button
            className="btn-wallet btn-phantom"
            onClick={signInWithPhantom}
            disabled={!!loading}
          >
            {loading === "phantom" ? "connecting..." : "sign in with phantom"}
          </button>
          <button
            className="btn-wallet btn-metamask"
            onClick={signInWithMetaMask}
            disabled={!!loading}
          >
            {loading === "metamask" ? "connecting..." : "sign in with metamask"}
          </button>
        </div>
        <div className="auth-divider">
          <span>or</span>
        </div>
        <div className="auth-section">
          <h3 className="section-label">seed phrase</h3>
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
