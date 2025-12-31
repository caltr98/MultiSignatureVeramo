# Server Demo (standalone)

This folder contains a standalone HTTP server and client to exercise the PoO + BLS multi-holder VP flow over HTTP.

## Requirements

- Node.js
- `yarn install` at the repo root (`MultiSignatureVeramo/`)

## Build

From `MultiSignatureVeramo/`:

- `yarn tsc -p tsconfig.json`

This compiles `src/server-demo/*.ts` into `src/server-demo/*.js`.

## Run server

From `MultiSignatureVeramo/`:

- ChainSafe backend: `VERAMO_BLS_BACKEND=chainsafe HOST=0.0.0.0 PORT=3001 node src/server-demo/veramo-server.js`
- noble backend: `VERAMO_BLS_BACKEND=noble HOST=0.0.0.0 PORT=3001 node src/server-demo/veramo-server.js`

Optional: require an API key for all non-GET endpoints:

- `API_KEY=change-me VERAMO_BLS_BACKEND=chainsafe HOST=0.0.0.0 PORT=3001 node src/server-demo/veramo-server.js`

When `API_KEY` is set, clients must send header `x-api-key: <API_KEY>`.

## Run client

In a second terminal (from `MultiSignatureVeramo/`):

- `BASE_URL=http://127.0.0.1:3001 HOLDERS=2 node src/server-demo/client.js`

If the server uses `API_KEY`, also set it for the client:

- `API_KEY=change-me BASE_URL=http://127.0.0.1:3001 HOLDERS=2 node src/server-demo/client.js`

## Notes

- This demo creates fresh DIDs/keys in the local Veramo SQLite store.
- Verification uses DID resolution; ensure the RPC/resolver config in `src/veramo/setup.ts` is reachable from where you run the server.

