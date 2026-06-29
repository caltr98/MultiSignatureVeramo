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

> **Prerequisites:** Node.js + Yarn (or npm), and an Ethereum RPC endpoint for `did:ethr` resolution (Sepolia or a local node). Configure the resolver in `src/veramo/setup.ts`.

```bash
# 1. Install dependencies
yarn install            # or: npm install

# 2. Compile TypeScript → JS
yarn tsc -p tsconfig.json

# 3. Run any script
node ./src/<script>.js
```

**Fastest way to see it work** — the printable VC/VP smoke test:

```bash
VERAMO_BLS_BACKEND=chainsafe node src/test/print_vc_vp_smoke.js
```

This prints — and attempts to verify — a VC and a VP, both carrying a Proof-of-Ownership.
*Verification resolves `did:ethr` and needs an RPC endpoint (default resolver: `http://127.0.0.1:8545`).*

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
| `plugins/veramo-plugin-multisig` | Core extension to the Veramo agent plugin for **creating and verifying multisignature credentials**. |
| `bls.extend-credential-w3c.ts` | Modified W3C credential plugin adding **multisignature support via BLS**. |
| `did-provider.ts` | Modified DID provider with **BLS key support** — publishes BLS public keys on the DID Document. |
| `kms-local-bls` | Extension of `kms-local` enabling **BLS keys for encryption/decryption**, giving agents those cryptographic capabilities. |

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

### 🛡️ Rogue-key attack simulation

A runnable simulation that verifies PoO/PoP binding is enforced for BLS aggregates.

```bash
# compile first
yarn tsc -p tsconfig.json
VERAMO_BLS_BACKEND=chainsafe node validation/rogue-key-attacks/rka_rogue_key_attack.js   # or: noble
```

- ✅ **Baseline (honest)** — aggregates honest BLS keys, attaches fresh PoOs → expected `verified: true` *(requires DID resolution via the configured Sepolia RPC)*.
- ❌ **Rogue attempt** — attacker forges a rogue BLS key (algebraically cancelling the honest PK), signs once, and reuses a **stale** PoO → expected `verified: false` if PoO binding works.

> Seeing RPC/DNS errors (e.g. `eth-sepolia.g.alchemy.com`)? Point `src/veramo/setup.ts` at a reachable resolver endpoint.

### 🖨️ Printable VC/VP smoke test

```bash
yarn install
yarn tsc -p tsconfig.json
VERAMO_BLS_BACKEND=chainsafe node src/test/print_vc_vp_smoke.js   # or: noble
```

Prints and attempts to verify a VC and a VP, each with a Proof-of-Ownership. *(Default resolver: `http://127.0.0.1:8545`.)*

<details>
<summary>📜 <b>Sample test mains</b> (click to expand)</summary>

<br>

Run after compiling (`yarn tsc -p tsconfig.json`):

| Script | Purpose |
| --- | --- |
| `Concerto-BLS` | BLS sample following the leader model: a leader aggregates signatures and BLS public keys and writes them onto a VC. |
| `create_key_key.ts` | Creates a BLS key + BLS key pair and stores the private key. **Run this before** the DID-creation script below. |
| `create-did-with-bls-key.ts` | Creates a DID with a BLS key and publishes it on the DID Document on Sepolia. |
| `create-vc-then-verify.ts` | Creates a VC with a BLS signature, recovers the public key from Sepolia, and verifies it. |
| `multisig-vc-creation.ts` | Creates a **multisig** VC, recovers public keys from Sepolia, and verifies the **aggregated** BLS signature. |
| `signature-with-bls.ts` | Signs a simple message with a BLS key. |

</details>

---

## 🌐 Server Demo

A small Express server + client that exercises the PoO + BLS multi-holder VP flow.

- **Server:** `src/server-demo/veramo-server.ts`
- **Client:** `src/server-demo/client.ts`
- **More docs:** `src/server-demo/README.md`

```bash
yarn install
yarn tsc -p tsconfig.json

# Terminal 1 — server
VERAMO_BLS_BACKEND=chainsafe node src/server-demo/veramo-server.js

# Terminal 2 — client
VERAMO_BLS_BACKEND=chainsafe node src/server-demo/client.js
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

It compiles the TypeScript sources (unless `SKIP_BUILD=1`), then loops over issuer counts **doubling** from `start_issuers` up to `end_issuers` (capped by `MAX_ISSUERS`). For each issuer count and claim size in `CLAIMS_LIST`, it records message sizes and benchmark timings for each enabled mode, writing CSVs to `experimental_results/`.

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
| `SKIP_BUILD` | `0` | Set `1` to skip the initial `yarn tsc` step. |
| `DEBUG` | `0` | Set `1` for shell tracing. |
| `DRY_RUN` | `0` | Set `1` to print commands without executing. |

</details>

### Baseline (no-multisig) EIP-712 / JWTProof2020 tests

```bash
# Benchmark
yarn tsc -p tsconfig.json && \
  node src/test_no_multisign_eip712/full_test_standard_veramo_eip712.js --claims 32 --size 1024 --issuers 8 --runs 5

# Message sizes
yarn tsc -p tsconfig.json && \
  node src/test_no_multisign_eip712/full_sizes_standard_test_main_eip712.js --claims 32 --size 1024 --issuers 8
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
