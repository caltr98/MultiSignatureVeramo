## Veramo Extended for Multisignature


Structure is as follows:
* plugins/veramo-plugin-multisig: The extension of veramo agent-plugin that allows for creating and verifying multisignature credentials.
* bls.extend-credential-w3c.ts: A modified version of the W3C credential veramo plugin that allows for multisignature support using bls.
* did-provider.ts: A modified version of the did-provider plugin that allows for support for bls keys, allowing to publish bls public keys on the DID Doc
* kms-local-bls: extension of the kms-local plugin that allows for using bls keys for encryption and decryption, adding those cryptographic capabilities to veramo agents

# BLS backend selection (ChainSafe vs noble-curves)

This repo supports switching the BLS implementation at runtime:

- `VERAMO_BLS_BACKEND=chainsafe` (default)
- `VERAMO_BLS_BACKEND=noble`

Example:

- `VERAMO_BLS_BACKEND=chainsafe node ...`
- `VERAMO_BLS_BACKEND=noble node ...`

# Testing mains
To test the multisignature functionality, you can use the following scripts:
* Concerto-BLS: A sample of BLS following the model with a leader that aggregates the signatures with bls key and public bls keys and puts them on a VC
* create-did-with-bls-key.ts: A script that creates a DID with a bls key and publishes it on the DID Doc on Sepolia
* create_key_key.ts: creates a bls key and a bls key pair and stores the private key, its needed to be executed before the above script
* create-vc-then-verify.ts: creates a VC with a bls signature and verifies it with the a BLS key and recovers from Sepolia the public key to then verify the signature
* multisig-vc-creation.ts: creates a multisig VC with a bls signature and verifies it with the a BLS key and recovers from Sepolia the public keys to then verify the aggregated BLS signature
* signature-with-bls.ts: signs a simple message with a bls key

# Printable VC/VP smoke test

This prints and (attempts to) verify:

- VC (with Proof-of-Ownership)
- VP (with Proof-of-Ownership)

Commands:

- `yarn install`
- `yarn tsc -p tsconfig.json`
- ChainSafe: `VERAMO_BLS_BACKEND=chainsafe node src/test/print_vc_vp_smoke.js`
- noble-curves: `VERAMO_BLS_BACKEND=noble node src/test/print_vc_vp_smoke.js`

Note: verification resolves `did:ethr` and requires an RPC endpoint configured in `src/veramo/setup.ts` (default resolver points to `http://127.0.0.1:8545`).

# Server demo (issuer/holder/verifier via HTTP)

This is a small express server + client that exercises the PoO+BLS multi-holder VP flow.

- Server: `src/server-demo/veramo-server.ts`
- Client: `src/server-demo/client.ts`
- More docs: `src/server-demo/README.md`

Run:

- `yarn install`
- `yarn tsc -p tsconfig.json`
- Terminal 1 (server): `VERAMO_BLS_BACKEND=chainsafe node src/server-demo/veramo-server.js`
- Terminal 2 (client): `VERAMO_BLS_BACKEND=chainsafe node src/server-demo/client.js`

Optional env vars:

- `PORT=3001` (server port)
- `HOST=0.0.0.0` (server bind host, use `0.0.0.0` for remote access)
- `API_KEY=...` (server requires `x-api-key` for non-GET requests)
- `BASE_URL=http://localhost:3001` (client server URL)
- `HOLDERS=2` (client number of holders)

# Usage
Install requirements with:
* `yarn install` (or `npm install`)

Then compile and run:
* `yarn tsc -p tsconfig.json` to compile TypeScript to JS
* `node ./src/<script>.js`
