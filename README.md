# torvex

encrypted, anonymous chat powered by wallet-based identity. no passwords, no emails — your seed phrase is your login.

## how it works

1. generate a 24-word bip39 seed phrase (or restore an existing one)
2. app derives an ed25519 keypair from the seed
3. server sends a random challenge → you sign it with your private key
4. server verifies the signature → you're in
5. all chat messages relay through websockets, identified only by public key

## stack

| layer    | tech                                  |
| -------- | ------------------------------------- |
| frontend | react + vite                          |
| backend  | node.js + express + ws                |
| database | supabase (postgresql) via drizzle orm |
| crypto   | bip39, tweetnacl (ed25519), bs58      |
| monorepo | npm workspaces + turborepo            |

## setup

```bash
git clone <repo-url> && cd torvex
npm install
```

### configure environment

**`apps/api/.env`**

```
PORT=4400
DATABASE_URL=postgresql://postgres:YOUR-PASSWORD@db.YOUR-PROJECT.supabase.co:5432/postgres
```

get your connection string from [supabase dashboard](https://supabase.com/dashboard) → project settings → database → connection string (uri)

**`apps/web/.env`** (defaults work for local dev)

```
VITE_API_URL=http://localhost:4400
VITE_WS_URL=ws://localhost:4400
```

### push database schema

```bash
cd apps/api
npm run db:push
```

### run

```bash
# terminal 1 — backend
cd apps/api && node src/server.js

# terminal 2 — frontend
cd apps/web && npx vite --port 6767
```

open http://localhost:6767

## project structure

```
torvex/
├── apps/
│   ├── api/          node.js websocket server + wallet auth
│   │   └── src/
│   │       ├── server.js
│   │       └── db/
│   │           ├── index.js
│   │           └── schema.js
│   └── web/          react chat frontend
│       └── src/
│           ├── App.jsx
│           ├── main.jsx
│           ├── styles.css
│           └── views/
│               ├── Auth.jsx
│               └── Chat.jsx
├── plan.md           full 5-phase roadmap
├── AGENTS.md         agent context for ai assistance
└── turbo.json
```

## roadmap

- [x] phase 1 — react web + node.js + websocket chat
- [x] phase 1.5 — bip39 wallet auth (challenge-response, no passwords)
- [ ] phase 2 — react native android port + qr code scanning
- [ ] phase 3 — rust backend rewrite + cassandra
- [ ] phase 4 — tor hidden service routing (paid tier)
- [ ] phase 5 — native swift ios + post-quantum crypto (ml-kem)

## license

mit
