# AGENTS.md — torvex project context

## project overview

torvex is a zero-knowledge encrypted chat with signal double ratchet, x3dh key agreement, and bip44 hd wallet auth. server never sees plaintext — stores only `[e2e:N]`. forward secrecy guaranteed via per-message dh ratchet steps.

## architecture

- **monorepo**: npm workspaces + turborepo
- **apps/api**: node.js express + websocket relay (port 4400)
- **apps/web**: react + vite frontend (port 6767)
- **database**: supabase postgresql via drizzle orm (ssl enforced)

## current phase: 2.0 (signal protocol + full features)

### cryptographic stack

| protocol        | implementation             | purpose                                                                |
| --------------- | -------------------------- | ---------------------------------------------------------------------- |
| bip44/slip-0010 | `crypto/keys.js`           | pure browser hd derivation via @noble/hashes hmac-sha512, no node deps |
| x3dh            | `crypto/x3dh.js`           | initial session key agreement with prekey bundles                      |
| double ratchet  | `crypto/ratchet.js`        | forward secrecy — per-message kdf chains + dh ratchet steps            |
| nacl.secretbox  | ratchet message encryption | xsalsa20-poly1305 symmetric encryption with ratchet-derived keys       |
| nacl.box        | x3dh dh operations         | curve25519 diffie-hellman for shared secret derivation                 |
| hkdf-sha256     | `@noble/hashes`            | kdf for root chain, message chain, x3dh shared secret                  |

### auth flow

1. user generates/restores 24-word bip39 mnemonic, or connects phantom/metamask
2. bip44 derives 3 keypairs: identity (sign), encryption (x25519), prekey (x25519)
3. sends identity pubkey to `POST /auth/challenge`
4. server returns `torvex-auth:{32-byte-nonce}:{timestamp}` (30s ttl, one-time)
5. client signs challenge, sends to `POST /auth/verify`
6. server returns jwt (hs256, jti, 24h expiry)
7. client generates signed prekey + 10 one-time prekeys, uploads to `POST /keys/bundle`
8. client connects websocket with `?token=jwt&encPub=x25519PublicKey`

### x3dh + double ratchet flow

1. alice clicks bob in sidebar → fetches bob's prekey bundle via `GET /keys/bundle/:pubkey`
2. alice runs `x3dhInitiator()` — 3 or 4 dh computations → hkdf → shared secret
3. alice inits sender ratchet with `initSender(sharedSecret, bob.signedPrekey)`
4. alice sends `x3dh_init` ws message with ephemeral key + first encrypted message
5. bob receives, runs `x3dhResponder()` → same shared secret, inits receiver ratchet
6. subsequent messages: `ratchetEncrypt()` / `ratchetDecrypt()` — dh ratchet step on direction change
7. each message gets unique key from kdf chain — forward secrecy + post-compromise security
8. ratchet states persisted in sessionStorage per peer

## file structure

```
torvex/
├── plan.md                      (full 5-phase roadmap, DO NOT EDIT)
├── AGENTS.md
├── README.md
├── LICENSE                      (source available license)
├── turbo.json
├── package.json                 (npm workspaces root)
├── apps/
│   ├── api/
│   │   ├── .env                 (PORT, DATABASE_URL, JWT_SECRET, ALLOWED_ORIGINS)
│   │   ├── drizzle.config.js
│   │   ├── package.json
│   │   └── src/
│   │       ├── server.js        (express + ws + auth + prekey endpoints + encrypted relay)
│   │       └── db/
│   │           ├── index.js     (drizzle client, ssl, pooling)
│   │           ├── schema.js    (users, messages, one_time_prekeys)
│   │           └── push.js      (manual schema push — drizzle-kit node v24 workaround)
│   └── web/
│       ├── .env                 (VITE_API_URL, VITE_WS_URL)
│       ├── vite.config.js       (buffer polyfill, proxy /auth /keys /profile /messages)
│       ├── index.html
│       ├── package.json
│       └── src/
│           ├── polyfills.js     (buffer global for browser crypto)
│           ├── main.jsx
│           ├── App.jsx
│           ├── styles.css       (dark theme, ws status, unread badges, responsive)
│           ├── crypto/
│           │   ├── keys.js      (bip44 slip-0010 hd derivation)
│           │   ├── x3dh.js      (extended triple diffie-hellman)
│           │   └── ratchet.js   (signal double ratchet protocol)
│           └── views/
│               ├── Auth.jsx     (seed + phantom + metamask auth + prekey upload)
│               └── Chat.jsx     (double ratchet chat, reconnect, notifications, offline decrypt, history persistence)
```

## security features

| layer          | protection                                                                       |
| -------------- | -------------------------------------------------------------------------------- |
| auth           | jwt hs256 + jti + revocation, 30s one-time challenges, csprng nonces             |
| http           | helmet (csp, hsts, xss, clickjack), cors lockdown, 8kb body limit, rate limiting |
| websocket      | 10 msg/sec rate limit, 32kb max payload, 5 conn/ip, encpub validation            |
| encryption     | signal double ratchet — per-message forward secrecy, x3dh session init           |
| key derivation | bip44/slip-0010 — deterministic hd paths from 24-word mnemonic                   |
| database       | ssl enforced, only `[e2e:N]` stored, connection pooling (max 10)                 |
| operational    | graceful shutdown, request id tracing, no error detail leakage                   |

## api endpoints

- `POST /auth/challenge` — get one-time challenge for pubkey
- `POST /auth/verify` — submit signed challenge for jwt
- `GET /auth/me` — verify jwt, get pubkey
- `POST /auth/revoke` — revoke current jwt
- `POST /keys/bundle` — upload prekey bundle (identity key, signed prekey, otps)
- `GET /keys/bundle/:pubkey` — fetch peer's prekey bundle (consumes one otp)
- `POST /profile/name` — set display name (max 32 chars)
- `GET /profile/:pubkey` — get peer's display name
- `GET /messages/pending` — fetch offline messages (marks as delivered)

## ws message types

- `user_joined` — new user connected (includes encPub)
- `user_left` — user disconnected
- `key_announce` — x25519 key exchange
- `x3dh_init` — x3dh session establishment (ephemeral key + first ratchet message)
- `chat` — ratchet-encrypted message (header.dh + header.n + header.pn + nonce + ciphertext)
- `chat_ack` — server confirms message relay
- `typing` — typing indicator (from, active bool)
- `read` — read receipt (from, msgId)
- `error` — rate limit or validation error

## db schema

### users

- `pubkey` (pk), `display_name`, `identity_key`, `signed_prekey`, `signed_prekey_sig`, `created_at`

### one_time_prekeys

- `id` (pk), `pubkey` (fk→users), `prekey_index`, `public_key`, `used`, `created_at`

### messages

- `id` (pk), `from_pubkey` (fk→users), `to_pubkey` (fk→users), `ciphertext`, `delivered`, `created_at`

## key conventions

- all file comments: exactly 2 lines at top, 10 words each
- no redundant variables — chain calls when possible
- functions <20 lines used once = inline them
- strict ordering: imports → enums → structs → logic
- env vars: backend uses `dotenv/config`, frontend uses `import.meta.env.VITE_*`
- identity = base58 ed25519 pubkey OR 0x eth address

## env vars

### apps/api/.env

- `PORT` — server port (default 4400)
- `DATABASE_URL` — supabase postgres connection string
- `JWT_SECRET` — 64+ char hex secret for jwt signing
- `ALLOWED_ORIGINS` — comma-separated cors origins (optional)
- `NODE_ENV` — set to `production` for hsts + trust proxy

### apps/web/.env

- `VITE_API_URL` — backend http url
- `VITE_WS_URL` — backend websocket url

## next phases (from plan.md)

- **phase 2**: react native android port + qr code scanning
- **phase 3**: rewrite backend in rust + cassandra
- **phase 4**: tor hidden service routing (paid tier)
- **phase 5**: native swift ios + post-quantum crypto (ml-kem)

## running the project

```bash
npm install
cd apps/api && node src/db/push.js
cd apps/api && node src/server.js
cd apps/web && npx vite --host
```
