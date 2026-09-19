<div align="center">

# 🎻 MultiSignatureVeramo

### *From Solo Issuing to an Orchestra*

**Aggregated BLS multi-signatures for W3C Verifiable Credentials — built on [Veramo](https://veramo.io).**
*Let a whole consortium co-sign one credential, verified with a single key and a single check.*

[![Paper DOI](https://img.shields.io/badge/Paper-10.1145%2F3748522.3779844-1f6feb?logo=acm&logoColor=white)](https://doi.org/10.1145/3748522.3779844)
[![Venue](https://img.shields.io/badge/SAC-'26-orange)](https://doi.org/10.1145/3748522.3779844)
[![Built with Veramo](https://img.shields.io/badge/built%20with-Veramo-5a45ff)](https://veramo.io)
[![BLS backends](https://img.shields.io/badge/BLS-ChainSafe%20%7C%20noble--curves-2ea44f)](#-bls-backend-selection)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
![TypeScript](https://img.shields.io/badge/TypeScript-3178c6?logo=typescript&logoColor=white)

<img src="https://github.com/user-attachments/assets/76f5822b-ce96-4497-9af9-12e322cb75bd" alt="Veramo multisignature plugin architecture" width="85%">

</div>

---

## 🪧 What is this?

**MultiSignatureVeramo** extends the [Veramo](https://veramo.io) SSI framework so that **multiple independent issuers can jointly sign a single W3C Verifiable Credential** using **aggregated BLS signatures**.

Instead of stapling *N* separate proofs onto a credential, the consortium produces **one** aggregated signature and **one** aggregated public key. A verifier can reject an invalid credential in a single cryptographic check — and only do the heavier per-issuer audit when it actually needs to.

Rogue-key attacks are kept out of the orchestra via a **Proof-of-Possession (PoP) / Proof-of-Ownership (PoO)** admission step, with a runnable attack simulation to prove the binding holds.

---

## 📑 Table of Contents

- [✨ Highlights](#-highlights)
- [🚀 Quick Start](#-quick-start)
- [🎯 Use Case: Cross-Consortium Issuance](#-use-case-cross-consortium-issuance)
- [⚡ Why Aggregated BLS?](#-why-aggregated-bls)
- [🧩 Architecture](#-architecture)
- [🔧 BLS Backend Selection](#-bls-backend-selection)
- [🧪 Testing](#-testing)
- [🌐 Server Demo](#-server-demo)
- [📊 Benchmarks](#-benchmarks)
- [📁 Experimental Results](#-experimental-results)
- [📚 Citation](#-citation)
- [📄 License](#-license)

---

## ✨ Highlights

- 🎼 **Aggregated BLS signing** — *N* issuers co-sign one VC; the verifier checks one signature against one `aggregated_bls_public_key`.
- ⚡ **O(1) fast-reject path** — validity is checked *before* any DID resolution; the O(*N*) membership/audit step runs only on demand.
- 🛡️ **Rogue-key defense** — PoP-gated issuer set + Proof-of-Ownership binding, shipped with a runnable rogue-key attack simulation.
- 🔌 **Drop-in Veramo plugins** — multisig agent plugin, BLS-extended W3C credential plugin, BLS-capable DID provider, and a BLS-enabled local KMS.
- 🔁 **Swappable BLS backends** — switch between **ChainSafe** and **noble-curves** at runtime with a single env var.
- 🌐 **End-to-end demos** — a printable VC/VP smoke test and an HTTP issuer / holder / verifier server demo.
- 📊 **Reproducible benchmarks** — one script benchmarks multisig vs. baseline vs. EIP-712 and writes CSVs, with a companion Jupyter notebook.

---

## 🚀 Quick Start

> **Prerequisites:** Node.js 22 or newer and Corepack with Yarn 1.22.22. The offline tests require no blockchain connection. The network demos also need an Ethereum RPC endpoint and the environment settings below.

This workspace targets **Veramo 7.0.1**, the latest stable release checked for this update. It follows Veramo 7's credential-provider API.

```bash
# 1. Install dependencies
corepack yarn install --frozen-lockfile

# 2. Build the four plugin packages and the demos
corepack yarn build

# 3. Exercise the agent APIs with in-memory DIDs and real signatures
corepack yarn test
```

Build output lives in `dist/` for the demos and `src/plugins/*/build/` for the packages. The workspace links local packages automatically; building them first makes their public exports available.

For network demos, copy [`.env.example`](.env.example) to `.env`, set `SEPOLIA_RPC_URL` and `VERAMO_DID_REGISTRY`, and fill in `VERAMO_KMS_SECRET_KEY`. Generate that 32-byte storage-encryption key with:

```bash
node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
```

Keep the same key when reopening an existing SQLite store. The demos read environment variables; `--env-file=.env` loads the file when starting Node. To print a VC and VP carrying Proof-of-Ownership:

```bash
node --env-file=.env dist/src/test/print_vc_vp_smoke.js
```

Verification resolves `did:ethr` through the configured RPC endpoint. The default URL is `http://127.0.0.1:8545`; a local node needs the matching DID registry deployment.

---

## 🎯 Use Case: Cross-Consortium Issuance

The sweet spot for aggregated BLS multi-signatures is **cross-organizational issuance**: several independent parties jointly attesting to the **same** VC payload — a consortium, coalition, supply chain, or multi-agency workflow.

> **Scenario — "Product Use Consent / Access Authorization"**
> A VC authorizing operation of a restricted component (say, a *psycho-frame interface*) on a high-risk product. The authorization is valid **only** when issued jointly by the full consortium:
>
> - 🏭 **Anaheim Electronics** — manufacturer
> - 🛡️ **Vist Foundation** — custodian / compliance gatekeeper
> - 🌍 **Earth Federation Forces** — regulator / operational authority
>
> The VC is held by a specific operator (holder DID). The consortium issues **one credential** that represents a single shared decision: *"these parties approved this exact payload."*

---

## ⚡ Why Aggregated BLS?

With **N separate signatures**, a verifier must verify *N* proofs, resolve *N* DID documents to fetch each issuer key, and only discovers an invalid credential **after** all that work.

With **one aggregated BLS signature**, the VC carries just `aggregated_bls_public_key` and `proof.signatureValue` — enabling a fast reject path:

|                           | N separate signatures      | Aggregated BLS                              |
| ------------------------- | -------------------------- | ------------------------------------------- |
| Proofs carried in VC/VP   | *N*                        | **1**                                       |
| Public keys               | *N*                        | **1** (`aggregated_bls_public_key`)         |
| DID resolutions to verify | *N*                        | **0** on the fast path *(N only for audit)* |
| Failure mode              | late — after *N* checks    | **immediate** — a single check              |

In short: **O(1) cryptographic validity check first**, and the **O(N) membership/audit check** only when policy actually requires proving *which* issuers formed the aggregate.

> 🔐 **PoP-gated issuer set (deployment assumption).** This repo assumes the consortium runs a **Proof-of-Possession admission step** for each issuer's BLS key *before* joint issuance. Only PoP-passed keys enter the signing roster used to build `aggregated_bls_public_key` — the standard mitigation against rogue-key attacks in BLS aggregation.

---

## 🧩 Architecture

Plugin additions on top of standard Veramo:

| Module | What it does |
| --- | --- |
| `src/plugins/bls-extend-credential-w3c` | Credential plugin and Veramo 7 BLS provider; partial signing, aggregation, and verification for VC/VP flows. |
| `src/plugins/did-manager-bls` | DID manager with the existing BLS key-management options. |
| `src/plugins/did-provider-BLS-Ethr` | Ethereum DID provider that can publish BLS verification keys. |
| `src/plugins/kms-local-bls` | BLS key generation, signing, aggregation, and shared verification; other key types use Veramo's local KMS. |

The custom `CredentialPlugin` keeps the existing multisignature agent methods and includes BLS and JWT providers. Additional formats are registered as Veramo 7 providers:

```typescript
import { CredentialPlugin } from '@veramo-community/credential-w3c-bls-multisig'
import { CredentialProviderEIP712 } from '@veramo/credential-eip712'

const credentials = new CredentialPlugin({
  blsBackend: 'chainsafe',
  providers: [new CredentialProviderEIP712()],
})
// Add credentials to createAgent({ plugins: [...] }).
```

Single BLS signatures use `proofFormat: 'bls'` with the standard `createVerifiableCredential`, `verifyCredential`, `createVerifiablePresentation`, and `verifyPresentation` methods. For aggregate documents, continue using `verifyMultisignatureCredential` / `verifyMultisignaturePresentation`, or the corresponding `verifyProofOfOwnershipMultisignature*` methods. Those methods check the custom BLS payload and signer roster; application trust, credential-status, and time policies remain the caller's responsibility.

`CredentialProviderBls` is also exported for applications that only need single BLS signatures inside the official `@veramo/credential-w3c` plugin. See the [credential package README](src/plugins/bls-extend-credential-w3c/README.md) for the migration details.

---

## 🔧 BLS Backend Selection

Switch the BLS implementation at runtime via a single environment variable:

| Backend | Value | Notes |
| --- | --- | --- |
| ChainSafe | `VERAMO_BLS_BACKEND=chainsafe` | **default** |
| noble-curves | `VERAMO_BLS_BACKEND=noble` | |

```bash
VERAMO_BLS_BACKEND=chainsafe node ...
VERAMO_BLS_BACKEND=noble     node ...
```

---

## 🧪 Testing

### Offline regression suite

```bash
corepack yarn build
corepack yarn test
```

The suite exercises both BLS backends, JWT and EIP-712 providers, the packaged exports, schema validation, VC/VP aggregation, ownership proofs, challenge/domain binding, and rejection of altered payloads and malformed proofs. It uses real keys and signatures with in-memory DID documents.

### 🛡️ Rogue-key attack simulation

A runnable simulation that verifies PoO/PoP binding is enforced for BLS aggregates.

```bash
# compile first
corepack yarn build
node --env-file=.env dist/validation/rogue-key-attacks/rka_rogue_key_attack.js
```

- ✅ **Baseline (honest)** — aggregates honest BLS keys, attaches fresh PoOs → expected `verified: true` *(requires DID resolution via the configured Sepolia RPC)*.
- ❌ **Rogue attempt** — attacker forges a rogue BLS key (algebraically cancelling the honest PK), signs once, and reuses a **stale** PoO → expected `verified: false` if PoO binding works.

> RPC/DNS failures require a reachable `SEPOLIA_RPC_URL` and a matching `VERAMO_DID_REGISTRY` in your environment.

### 🖨️ Printable VC/VP smoke test

```bash
corepack yarn build
node --env-file=.env dist/src/test/print_vc_vp_smoke.js
```

Prints and attempts to verify a VC and a VP, each with a Proof-of-Ownership. *(Default resolver: `http://127.0.0.1:8545`.)*

<details>
<summary>📜 <b>Sample test mains</b> (click to expand)</summary>

<br>

Run after `corepack yarn build`, using the corresponding path under `dist/`:

| Script | Purpose |
| --- | --- |
| `src/test/print_vc_vp_smoke.ts` | Prints and verifies a multi-issuer VC and a multi-holder VP. |
| `src/test/full_test_main.ts` | Runs the multisignature benchmark. |
| `src/test_no_multisign/full_test_standard_veramo.ts` | Runs the standard credential benchmark. |
| `src/test_no_multisign_eip712/full_test_standard_veramo_eip712.ts` | Runs the EIP-712 baseline. |
| `validation/rogue-key-attacks/rka_rogue_key_attack.ts` | Exercises the honest and rogue-key cases. |

</details>

---

## 🌐 Server Demo

A small Express server + client that exercises the PoO + BLS multi-holder VP flow.

- **Server:** `src/server-demo/veramo-server.ts`
- **Client:** `src/server-demo/client.ts`
- **More docs:** `src/server-demo/README.md`

```bash
corepack yarn install --frozen-lockfile
corepack yarn build

# Terminal 1 — server
node --env-file=.env dist/src/server-demo/veramo-server.js

# Terminal 2 — client
node --env-file=.env dist/src/server-demo/client.js
```

<details>
<summary>⚙️ <b>Optional environment variables</b></summary>

<br>

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `3001` | Server port. |
| `HOST` | `0.0.0.0` | Server bind host (use `0.0.0.0` for remote access). |
| `BASE_URL` | `http://localhost:3001` | Client → server URL. |
| `HOLDERS` | `2` | Number of holders (client). |

</details>

---

## 📊 Benchmarks

The repo ships a convenience script, `benchmark.sh`, that automates performance testing for **multisignature**, **standard (no-multisig)**, and the **EIP-712 baseline** — no need to invoke individual Node scripts by hand.

```bash
./benchmark.sh <start_issuers> <end_issuers>
```

Export the demo environment variables before running this Bash script; it does not load `.env` itself. It builds the workspace (unless `SKIP_BUILD=1`) and loops over issuer counts **doubling** from `start_issuers` up to `end_issuers` (capped by `MAX_ISSUERS`). For each issuer count and claim size in `CLAIMS_LIST`, it records message sizes and benchmark timings for each enabled mode, writing CSVs to `experimental_results/`.

```bash
# Example: 2 → 32 issuers, larger messages, multisig only
CLAIMS_LIST="16 32" SIZE=1024 RUN_STANDARD=0 RUN_EIP712=0 ./benchmark.sh 2 32
```

<details>
<summary>⚙️ <b><code>benchmark.sh</code> environment variables</b></summary>

<br>

| Variable | Default | Purpose |
| --- | --- | --- |
| `MAX_ISSUERS` | `32` | Largest issuer count to test (stops when doubling would exceed it). |
| `CLAIMS_LIST` | `"16 128"` | Space-separated list of claim counts to benchmark. |
| `SIZE` | `64` | Size of each claim (bytes). |
| `RUNS` | `1000` | Iterations for multisig and standard benchmarks. |
| `EIP712_RUNS` | `30` | Iterations for EIP-712 benchmarks (no sample VC printing). |
| `RUN_MULTISIG` | `1` | Set `0` to skip multisignature benchmarks. |
| `RUN_STANDARD` | `1` | Set `0` to skip standard (no-multisig) benchmarks. |
| `RUN_EIP712` | `1` | Set `0` to skip EIP-712 baseline benchmarks. |
| `RESUME` | `0` | If `1`, skip issuer counts already present in the output CSVs. |
| `PRUNE` | `0` | If `1`, delete existing rows for an issuer before running. |
| `SKIP_BUILD` | `0` | Set `1` to skip the initial workspace build. |
| `DEBUG` | `0` | Set `1` for shell tracing. |
| `DRY_RUN` | `0` | Set `1` to print commands without executing. |

</details>

### Baseline (no-multisig) EIP-712 / JWTProof2020 tests

```bash
# Benchmark
corepack yarn build
node --env-file=.env dist/src/test_no_multisign_eip712/full_test_standard_veramo_eip712.js --claims 32 --size 1024 --issuers 8 --runs 5

# Message sizes
node --env-file=.env dist/src/test_no_multisign_eip712/full_sizes_standard_test_main_eip712.js --claims 32 --size 1024 --issuers 8
```

- `VERAMO_DB_EIP712=database_eip712.sqlite` — optional DB filename override (default `database_eip712.sqlite`).
- EIP-712 verification uses the remote `ethr-did-resolver` (needs RPC access and successful DID resolution).

---

## 📁 Experimental Results

- 📓 **Notebook:** `MultiSignaturePerformance.ipynb`
- 📂 **CSV outputs:** `experimental_results/`

| File pattern | Contents |
| --- | --- |
| `benchmark_results_claims*_size*.csv` | Multisig benchmark timings. |
| `message_sizes_claims*_size*.csv` | Multisig message sizes. |
| `benchmark_standard*_claims*_size*.csv` | Baseline (no-multisig) benchmark timings. |
| `message_sizes_standard*_claims*_size*.csv` | Baseline (no-multisig) message sizes. |
| `PoPBLSKeysExchangesmessage_sizes.csv` | PoP + BLS key-exchange sizes. |

Benchmark/size scripts write to `experimental_results/` by default (including via `benchmark.sh`).

---

## 📚 Citation

If you use this work, please cite:

> Calogero Turco, Andrea De Salve, Paolo Mori, and Laura Ricci. 2026. *From Solo Issuing to an Orchestra: Design and Seamless Augmentation of Self-Sovereign Identity for Multi-Signature Verifiable Credentials.* In Proceedings of the 41st ACM/SIGAPP Symposium on Applied Computing (SAC '26). Association for Computing Machinery, New York, NY, USA, 503–505. https://doi.org/10.1145/3748522.3779844

```bibtex
@inproceedings{turco2026orchestra,
  author    = {Turco, Calogero and De Salve, Andrea and Mori, Paolo and Ricci, Laura},
  title     = {From Solo Issuing to an Orchestra: Design and Seamless Augmentation of Self-Sovereign Identity for Multi-Signature Verifiable Credentials},
  booktitle = {Proceedings of the 41st ACM/SIGAPP Symposium on Applied Computing (SAC '26)},
  year      = {2026},
  pages     = {503--505},
  publisher = {Association for Computing Machinery},
  address   = {New York, NY, USA},
  doi       = {10.1145/3748522.3779844}
}
```

---

## 📄 License

Released under the **MIT License** — see [`LICENSE`](LICENSE) for details.
