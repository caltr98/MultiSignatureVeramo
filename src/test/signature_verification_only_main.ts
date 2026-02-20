import { cleanup, setup_bls_agents } from "./enviroment_setup.js";
import { generateVCPayload } from "./generate_VC_payload.js";
import {
    generatePayloadToSign,
    getBlsKeyHex,
    VCAggregateKeysToSignatures,
    VCAggregateKeysToSignaturesWithBenchmark
} from "./issuers_test.js";
import fs from 'fs';
import path from 'path';
import canonicalizeLib from "canonicalize";
import { VerifiableCredential, VerifiablePresentation } from "@veramo/core-types";
import { createSingleHolderPresentation, storeCredential } from "./holder_test.js";
import { verifyMultiSignatureVC, verifyVP } from "./verifier_test.js";
import { performance } from "node:perf_hooks";
import bls from "@chainsafe/bls";
import { hexToBytes } from "@veramo/utils";

const canonicalize = canonicalizeLib as unknown as (input: unknown) => string | undefined
const RESULTS_CSV = path.resolve('./benchmark_results.csv');

if (!fs.existsSync(RESULTS_CSV)) {
    const header = 'Issuers,StepName,avg_ms,std_ms\n';
    fs.writeFileSync(RESULTS_CSV, header);
}

function parseArg(name: string, defaultValue: number): number {
    const index = process.argv.indexOf(`--${name}`)
    if (index !== -1 && process.argv[index + 1]) {
        const val = parseInt(process.argv[index + 1])
        if (!isNaN(val)) return val
    }
    return defaultValue
}

const claims_n = parseArg('claims', 32)
const claims_size = parseArg('size', 1024)
const n_issuers = parseArg('issuers', 12)
const RUNS = parseArg('runs', 10)

type BenchmarkResults = Record<string, number>

function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms))
}

const issuers = await setup_bls_agents(n_issuers);
const holder = (await setup_bls_agents(1))[0];

await getBlsKeyHex(issuers[0].kid_bls)

const allTimings: Record<string, number[]> = {}

for (let i = 0; i < RUNS; i++) {
    console.log(`\n Run ${i + 1} of ${RUNS}`)

    const timings: BenchmarkResults = {}

    // Generate aggregated multisig VC with benchmarking inside the function
    const res = await VCAggregateKeysToSignaturesWithBenchmark(
        issuers,
        holder.did,
        claims_n,
        claims_size
    )
    const VC = res.vc as VerifiableCredential

    // Benchmark ONLY Verify MultiSig VC no PoO
    const start = performance.now()
    // Prepare payload for verification
    const payloadToVerify = {
        '@context': VC['@context'],
        multi_issuers: VC.multi_issuers,
        credentialSubject: VC.credentialSubject,
        type: VC.type,
        aggregated_bls_public_key: VC.aggregated_bls_public_key,
    };

    const payload = canonicalize(payloadToVerify)
    if (!payload) throw new Error('Failed to canonicalize VC')
    const message = Uint8Array.from(Buffer.from(payload, 'utf-8'))

    const aggregatedPublicKey = bls.PublicKey.fromHex(VC.aggregated_bls_public_key);

    const valid = bls.verify(aggregatedPublicKey, message, hexToBytes(VC.proof.signatureValue))
    const end = performance.now()
    timings['Verify MultiSig VC no PoO'] = end - start

    console.log(valid)

    for (const [label, value] of Object.entries(timings)) {
        if (!allTimings[label]) {
            allTimings[label] = []
        }
        allTimings[label].push(value)
    }

    await sleep(100) // cooldown for alchemy!
}

const summary: Record<string, { avg_in_ms: number; std_dev: number }> = {}
for (const [label, values] of Object.entries(allTimings)) {
    const avg_in_ms = values.reduce((a, b) => a + b, 0) / values.length
    const std_dev = Math.sqrt(
        values.reduce((sum, x) => sum + Math.pow(x - avg_in_ms, 2), 0) / values.length
    )
    summary[label] = { avg_in_ms, std_dev }
}

const csvLines: string[] = [];
for (const [step, stats] of Object.entries(summary)) {
    const avg = stats.avg_in_ms.toFixed(6);
    const std = stats.std_dev.toFixed(6);
    csvLines.push(`${n_issuers},${step},${avg},${std}`);
}

fs.appendFileSync(RESULTS_CSV, csvLines.join('\n') + '\n');
console.log(`Appended results for ${n_issuers} issuers to ${RESULTS_CSV}`);

console.log(`\nAverage timings and standard deviation with ${claims_n} claims of ${claims_size}, ${n_issuers} issuers, and ${RUNS} runs:`)
console.table(summary)

await cleanup()
