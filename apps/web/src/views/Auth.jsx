// torchat web - wallet auth with bip39 seed generation
// creates keypair from mnemonic and signs server challenge

import React, { useState } from "react";
import * as bip39 from "bip39";
import nacl from "tweetnacl";
import bs58 from "bs58";
import { Buffer } from "buffer";

window.Buffer = Buffer;

const API = import.meta.env.VITE_API_URL || "http://localhost:4400";

function deriveKeypair(mnemonic) {
  const seed = bip39.mnemonicToSeedSync(mnemonic).slice(0, 32);
  return nacl.sign.keyPair.fromSeed(seed);
}

export default function Auth({ onAuth }) {
  const [mnemonic, setMnemonic] = useState("");
  const [phase, setPhase] = useState("start");
  const [error, setError] = useState("");
  const [generatedPhrase, setGeneratedPhrase] = useState("");

  async function signIn(phrase) {
    setError("");
    try {
      const keypair = deriveKeypair(phrase);
      const pubkey = bs58.encode(keypair.publicKey);

      const challengeRes = await fetch(`${API}/auth/challenge`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pubkey }),
      });
      const { challenge } = await challengeRes.json();
      if (!challenge) throw new Error("failed to get challenge");

      const msgBytes = new TextEncoder().encode(challenge);
      const signature = bs58.encode(nacl.sign.detached(msgBytes, keypair.secretKey));

      const verifyRes = await fetch(`${API}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pubkey, signature }),
      });
      const data = await verifyRes.json();
      if (!verifyRes.ok) throw new Error(data.error);

      onAuth({ token: data.token, pubkey: data.pubkey });
    } catch (err) {
      setError(err.message);
    }
  }

  function generateWallet() {
    const phrase = bip39.generateMnemonic(256);
    setGeneratedPhrase(phrase);
    setPhase("generated");
  }

  if (phase === "generated") {
    return (
      <div className="auth-wrap">
        <div className="auth-card">
          <h1 className="logo">torchat</h1>
          <p className="tagline">your new wallet seed phrase</p>
          <div className="seed-display">
            {generatedPhrase.split(" ").map((word, i) => (
              <span key={i} className="seed-word">
                <em>{i + 1}.</em> {word}
              </span>
            ))}
          </div>
          <p className="warning">write this down. it is your only login. lose it and you lose access forever.</p>
          <button onClick={() => signIn(generatedPhrase)}>i saved it — sign in</button>
          {error && <p className="error">{error}</p>}
          <p className="switch" onClick={() => setPhase("start")}>back</p>
        </div>
      </div>
    );
  }

  if (phase === "restore") {
    return (
      <div className="auth-wrap">
        <div className="auth-card">
          <h1 className="logo">torchat</h1>
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
              if (!bip39.validateMnemonic(mnemonic.trim())) {
                setError("invalid seed phrase");
                return;
              }
              signIn(mnemonic.trim());
            }}
          >
            sign in with seed
          </button>
          <p className="switch" onClick={() => setPhase("start")}>back</p>
        </div>
      </div>
    );
  }

  return (
    <div className="auth-wrap">
      <div className="auth-card">
        <h1 className="logo">torchat</h1>
        <p className="tagline">encrypted. anonymous. yours.</p>
        <button onClick={generateWallet}>create new wallet</button>
        <button className="btn-secondary" onClick={() => setPhase("restore")}>
          restore from seed phrase
        </button>
      </div>
    </div>
  );
}
