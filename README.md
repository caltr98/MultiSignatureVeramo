## Veramo Extended for Multisignature

## Experimental results (CSV) + notebook

- Notebook: `MultiSignaturePerformance.ipynb`
- All generated/collected CSV outputs: `experimental_results/`
  - Multisig benchmark timings: `experimental_results/benchmark_results_claims*_size*.csv`
  - Multisig message sizes: `experimental_results/message_sizes_claims*_size*.csv`
  - Baseline (no multisig) benchmarks: `experimental_results/benchmark_standard*_claims*_size*.csv`
  - Baseline (no multisig) message sizes: `experimental_results/message_sizes_standard*_claims*_size*.csv`
  - PoP + BLS key-exchange sizes: `experimental_results/PoPBLSKeysExchangesmessage_sizes.csv`

The benchmark/size scripts now write to `experimental_results/` by default (including when run via `benchmark.sh`).

Structure is as follows:
* plugins/veramo-plugin-multisig: The extension of veramo agent-plugin that allows for creating and verifying multisignature credentials.
* bls.extend-credential-w3c.ts: A modified version of the W3C credential veramo plugin that allows for multisignature support using bls.
* did-provider.ts: A modified version of the did-provider plugin that allows for support for bls keys, allowing to publish bls public keys on the DID Doc
* kms-local-bls: extension of the kms-local plugin that allows for using bls keys for encryption and decryption, adding those cryptographic capabilities to veramo agents

# Use Case: Cross-Consortium Issuance (Joint Attestation)

The “best fit” for aggregated BLS multi-signatures is cross-organizational issuance: **multiple independent parties jointly attesting to the same VC payload** (a consortium, coalition, supply chain, or multi-agency workflow).

## Example scenario

Imagine a “Product Use Consent / Access Authorization” VC for operating a restricted component (e.g., a psycho-frame interface) on a high-risk product.

The authorization is only valid when it is issued jointly by a consortium:

- **Anaheim Electronics** (manufacturer)
- **Vist Foundation** (custodian / compliance gatekeeper)
- **Earth Federation Forces** (regulator / operational authority)

The VC is held by a specific operator (holder DID). The consortium issues **one credential** that represents a single, shared decision: *“these parties approved this exact payload”*.

## Why aggregated BLS helps (vs “N separate signatures”)

If you do not use an aggregated signature, the verifier typically has to:

- Verify **N independent signatures/proofs** (and carry N proofs in the VC/VP).
- Resolve **N DID documents / verification methods** to fetch each issuer public key.
- Fail late (you only know it’s invalid after doing N verifications and N resolutions).

With an aggregated BLS signature, the VC carries:

- `aggregated_bls_public_key` (one public key)
- `proof.signatureValue` (one aggregated signature)

That enables a **fast reject path**:

- If the aggregate signature does not verify against `aggregated_bls_public_key`, you can stop immediately (single check).

Optionally, if your verifier policy requires “prove which exact issuers formed the aggregate”, you can do a second step:

- Resolve the issuers’ BLS keys (N DID resolutions) and recompute the aggregate key, then check it matches `aggregated_bls_public_key`.

In other words: **O(1) cryptographic validity check first**, and only do the **O(N) membership/audit check** when you actually need it.

## Important assumption (PoP-gated issuer set)

This repo’s intended deployment model assumes the consortium performs a **Proof-of-Possession (PoP) admission step** for each issuer’s BLS key *before* issuing jointly.

Practical meaning:

- The issuer set is “PoP-gated”: only keys that passed PoP are included in the signing roster used to build `aggregated_bls_public_key`.
- This is the standard mitigation against rogue-key issues in BLS key aggregation.

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
- `BASE_URL=http://localhost:3001` (client server URL)
- `HOLDERS=2` (client number of holders)

# Usage
Install requirements with:
* `yarn install` (or `npm install`)

Then compile and run:
* `yarn tsc -p tsconfig.json` to compile TypeScript to JS
* `node ./src/<script>.js`

# Baseline (no multisig) EIP712 or JWTProof2020 test tests

- Benchmark: `yarn tsc -p tsconfig.json && node src/test_no_multisign_eip712/full_test_standard_veramo_eip712.js --claims 32 --size 1024 --issuers 8 --runs 5`
- Message sizes: `yarn tsc -p tsconfig.json && node src/test_no_multisign_eip712/full_sizes_standard_test_main_eip712.js --claims 32 --size 1024 --issuers 8`

Notes / env vars:

- `VERAMO_DB_EIP712=database_eip712.sqlite` (optional DB filename override; defaults to `database_eip712.sqlite`)
- EIP712 verification uses remote `ethr-did-resolver` (requires RPC access and DID resolution to succeed).

## Benchmark script for automated tests

This repository includes a convenient shell script `benchmark.sh` that can automate performance testing for both multisignature and no‑multisignature modes as well as the EIP‑712 baseline.  Rather than invoking individual Node.js scripts by hand, you can run:

```
./benchmark.sh <start_issuers> <end_issuers>
```

The script will compile the TypeScript sources (unless you set `SKIP_BUILD=1`) and then loop over issuer counts doubling from `start_issuers` up to `end_issuers` (not exceeding `MAX_ISSUERS`).  For each issuer count and claim size in `CLAIMS_LIST` it will record both message sizes and benchmark timings for multisignature, standard (no multisig) and EIP‑712 modes (unless you disable one of them with the variables below).  Output CSV files are written to the `experimental_results/` directory.

You can customise the benchmark by exporting environment variables before invoking the script:

| Variable | Default | Purpose |
|---|---|---|
| `MAX_ISSUERS` | `32` | Largest number of issuers to test (script stops when doubling would exceed this number). |
| `CLAIMS_LIST` | `"16 128"` | Space‑separated list of claim counts to benchmark. |
| `SIZE` | `64` | Size of each claim (in bytes). |
| `RUNS` | `1000` | Number of iterations for multisig and standard benchmarks. |
| `EIP712_RUNS` | `30` | Number of iterations for EIP‑712 benchmarks (no sample VC printing). |
| `RUN_MULTISIG` | `1` | Set to `0` to skip multisignature benchmarks. |
| `RUN_STANDARD` | `1` | Set to `0` to skip the standard (no multisig) benchmarks. |
| `RUN_EIP712` | `1` | Set to `0` to skip the EIP‑712 baseline benchmarks. |
| `RESUME` | `0` | If set to `1`, rows already present in the output CSVs for a given issuer count will be skipped. |
| `PRUNE` | `0` | If set to `1`, existing rows for a given issuer are deleted before running. |
| `SKIP_BUILD` | `0` | Set to `1` to skip the initial `yarn tsc` compilation step. |
| `DEBUG` | `0` | Set to `1` for shell tracing of commands. |
| `DRY_RUN` | `0` | Set to `1` to print the commands without executing them. |

For example, to benchmark from 2 to 32 issuers with larger messages and only run the multisignature tests, you could run:

```bash
CLAIMS_LIST="16 32" SIZE=1024 RUN_STANDARD=0 RUN_EIP712=0 ./benchmark.sh 2 32
```
