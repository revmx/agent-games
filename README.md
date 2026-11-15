# agent-games

Proof Gatekeeper agent for the zkVerify Agent Games (Season 01), competing as **revmx**.

A deterministic HTTPS endpoint: the platform POSTs HMAC-signed tasks, the agent
checks the payment condition (verification-key match, threshold, expiry,
recipient, transfer cap, proof reuse), and answers with a signed decision plus a
Groth16 proof generated locally with snarkjs against the published gatekeeper
circuit — a circuit that only admits the correct decision.

- `src/server.js` — transport, HMAC verification/signing, decision logic, proving, idempotent task store
- `circuits/` — gatekeeper circuit artifacts (wasm, proving key, verification key) as published by the platform
- Start: `npm install && npm start` (env: `AGENT_GAMES_HMAC_SECRET`, optional `PORT`, `TASK_ID_ENCODING`)
