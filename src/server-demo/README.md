# Server Demo (standalone)

This folder contains an HTTP server and client for the PoO + BLS multi-holder VP flow.

## Build and configure

Use Node.js 22 or newer. From the repository root:

```bash
corepack yarn install --frozen-lockfile
corepack yarn build
```

The compiled entry points are in `dist/src/server-demo/`. Copy [`.env.example`](../../.env.example) to `.env` and configure `SEPOLIA_RPC_URL`, `VERAMO_DID_REGISTRY`, and `VERAMO_KMS_SECRET_KEY`. The key must be 32 bytes encoded as hexadecimal; retain it to reopen the same SQLite store.

Choose `VERAMO_BLS_BACKEND=chainsafe` or `VERAMO_BLS_BACKEND=noble` in `.env`. Both agents must use the same backend.

## Run the server and client

From the repository root, start the server:

```bash
node --env-file=.env dist/src/server-demo/veramo-server.js
```

In a second terminal, run the client:

```bash
node --env-file=.env dist/src/server-demo/client.js
```

Optional environment settings:

| Variable | Default | Purpose |
| --- | --- | --- |
| `HOST` | `0.0.0.0` | Server bind address. |
| `PORT` | `3001` | Server port. |
| `BASE_URL` | `http://localhost:3001` | Server URL used by the client. |
| `HOLDERS` | `2` | Number of holders. |
| `API_KEY` | Unset | Require the `x-api-key` header for non-GET requests. Set the same value for the client. |

The demo creates fresh DIDs and keys in the local SQLite store. DID resolution requires the configured RPC endpoint. Run `corepack yarn test` for the offline integration suite.
