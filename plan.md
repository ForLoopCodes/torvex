AI AGENTS ARE NOT ALLOWED TO CHANGE THIS FILE'S CONTENTS.

# plan.md: torchat architecture & execution

## 1. the original vision

> project idea: torchat app - android and apple - uses tor network and sign in with your wallet (bitcoin/solana/eth) to chat with others, find people by scanning their qr or their wallet address, send encrypted (even more encrypted than whatsapp and signal and telegram, i mean really true quantum safe encryption), no need for password login, just login with wallet. but the thing is you dont need to pay btc/eth/sol for each chat, its not a web3 app, chat completely anonymously with your friends, no mitm assured
> give me some papers, plan, summary, tech stack (native, i need the ui to be fast, clean, and use gpu, not react native it sucks) of how to make this app
> the normal encrypted chat will be free but paid chat has quantum safe, tor, and wallet sign in
> about the wallet, i mean not login by phantom or metamask, the app will itself be one wallet app which will encrypt chats w/ your keys, you can create wallet, sent transactions, but also use the bip and private keys to log in to your account
> please note i am a normal nodejs developer and im gonna vibe code it a lot, make me know what the ai will actually be doing and it should have no flaws

## 2. foundational reading & references

to code this without flaws, u cannot rely purely on ai hallucinations. u must understand the math and the protocols. read these before u write the rust core:

* **the double ratchet protocol:** [read the official signal specification here](https://signal.org/docs/specifications/doubleratchet/). this guarantees forward secrecy and post-compromise security for your free tier.
* **post-quantum cryptography (ml-kem):** [read the nist fips 203 specification](https://csrc.nist.gov/pubs/fips/203/final). this is the module-lattice-based key-encapsulation mechanism (formerly kyber) u will use for the paid tier.
* **bip39 & bip44:** [read the bitcoin improvement proposals](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki). this dictates how u derive the solana/eth/btc keys and the specific sub-keys for chat encryption from a single 24-word seed phrase.

## 3. the turborepo monorepo structure

u will use a turborepo to share types and cryptography across the web, android, and apple apps.

* `apps/web` (react frontend for phase 1)
* `apps/android` (react native for phase 2)
* `apps/ios` (swift native for phase 5)
* `apps/api` (node.js backend for early phases)
* `packages/crypto` (rust-compiled webassembly for web/react native, native bindings for swift)

## 4. execution phases

### phase 1: react web + node.js + supabase

**goal:** establish the core web2 infrastructure and the initial user interface.

* **frontend:** react.js (vite) hosted on vercel.
* **backend:** node.js websocket signaling server.
* **database:** supabase (postgresql) for user public keys and encrypted message queues.
* **action:** build the chat interface. right now, use standard dummy passwords just to get the websockets passing messages back and forth reliably.

### phase 1.5: the crypto wallet auth test (crucial)

**goal:** replace the dummy passwords with true cryptographic identity.

* **action:** implement bip39 wallet generation in the browser.
* **auth flow:** the user generates a seed phrase. the app derives their solana public key. the node.js backend sends a random string (challenge). the frontend signs the string with the private key. the backend verifies the signature and opens the websocket.
* **milestone:** u can now "log in" without a password, purely using the wallet. no other features are built until this is flawless.

### phase 2: the android port (react native)

**goal:** bring the validated web logic to a mobile environment.

* **frontend:** react native. since u already wrote the react web app, u simply port the logic and components.
* **features:** integrate the device camera for scanning qr codes containing wallet addresses.
* **encryption:** implement standard web-crypto api double ratchet (signal protocol) for the free tier users over standard internet.

### phase 3: the dark forest backend (rust + cassandra)

**goal:** scale the backend to handle massive throughput and prepare for decentralized routing.

* **backend rewrite:** rewrite the node.js signaling server in **rust** using `tokio` to handle heavy concurrency.
* **database migration:** swap supabase out for a local **apache cassandra** cluster.  cassandra handles decentralized, heavy-write workloads perfectly.
* **hosting:** move off vercel. deploy the rust backend and cassandra to a virtual private server (vps).

### phase 4: tor network routing (paid tier)

**goal:** eliminate ip tracking and man-in-the-middle attacks.

* **network:** configure the rust vps to run as a tor hidden service.
* **client integration:** embed the `arti` (rust tor implementation) crate into your mobile apps. the paid tier toggle routes all websocket traffic through the `.onion` address instead of the clearnet.

### phase 5: native apple & post-quantum completion

**goal:** total fulfillment of the vision.

* **ios app:** rewrite the frontend in native swift/swiftui for maximum gpu acceleration and flawless apple hardware integration. bind it to the rust crypto core using `uniffi`.
* **quantum safety:** integrate `pqcrypto` (ml-kem/fips 203) into the rust core. the initial handshake for paid users scanning a qr code will now be quantum-resistant.