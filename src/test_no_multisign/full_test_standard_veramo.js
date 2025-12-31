import { cleanup, setup_agents } from './enviroment_setup.js';
import { storeCredential, createPresentation } from './holder_test.js';
import { verifyVP, verifyAllVCsInVP } from './verifier_test.js';
import fs from 'fs';
import path from 'path';
import { generateVCPayload } from "./generate_VC_payload.js";
import { agent } from "../veramo/setup.js";
const RESULTS_CSV = path.resolve('./benchmark_standard.csv');
if (!fs.existsSync(RESULTS_CSV)) {
    fs.writeFileSync(RESULTS_CSV, 'Issuers,StepName,avg_ms,std_ms\n');
}
function parseArg(name, defaultValue) {
    const index = process.argv.indexOf(`--${name}`);
    if (index !== -1 && process.argv[index + 1]) {
        const val = parseInt(process.argv[index + 1]);
        if (!isNaN(val))
            return val;
    }
    return defaultValue;
}
const claims_n = parseArg('claims', 32);
const claims_size = parseArg('size', 1024);
const n_issuers = parseArg('issuers', 8);
const RUNS = parseArg('runs', 5);
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
async function benchmarkStep(label, results, fn) {
    const start = performance.now();
    const result = await fn();
    const end = performance.now();
    results[label] = end - start;
    return result;
}
// MAIN RUN
const allTimings = {};
const issuers = await setup_agents(n_issuers); // one agent per VC
const holder = (await setup_agents(1))[0];
for (let i = 0; i < RUNS; i++) {
    console.log(`\nRun ${i + 1} of ${RUNS}`);
    const timings = {};
    const credentials = [];
    timings["Issue VCs"] = timings["Store VCs"] = 0;
    let now, start;
    for (const issuer of issuers) {
        const payload = await generateVCPayload(holder.did, claims_n, claims_size, 42);
        start = performance.now();
        // ---- Standard Veramo VC Creation ----
        const vc = await agent.createVerifiableCredential({
            credential: {
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                type: ['VerifiableCredential'],
                issuer: { id: issuer.did },
                credentialSubject: payload.credentialSubject,
            },
            proofFormat: 'jwt',
        });
        now = performance.now();
        timings[`Issue VCs`] = timings[`Issue VCs`] + now - start;
        credentials.push(vc);
        start = performance.now();
        await storeCredential(vc);
        now = performance.now();
        timings[`Store VCs`] = timings[`Store VCs`] + now - start;
    }
    const vp = await benchmarkStep('Create VP (N VCs)', timings, () => createPresentation(credentials, holder.did));
    await benchmarkStep('Verify VP (N VCs)', timings, () => verifyVP(vp));
    const results = await verifyAllVCsInVP(vp, timings);
    if (results.some(r => !r.verified)) {
        throw new Error('One or more embedded VCs failed verification');
    }
    for (const [label, value] of Object.entries(timings)) {
        if (!allTimings[label]) {
            allTimings[label] = [];
        }
        allTimings[label].push(value);
    }
    await sleep(200);
}
// ---- Compute Stats ----
const summary = {};
for (const [label, values] of Object.entries(allTimings)) {
    const avg_in_ms = values.reduce((a, b) => a + b, 0) / values.length;
    const std_dev = Math.sqrt(values.reduce((sum, x) => sum + Math.pow(x - avg_in_ms, 2), 0) / values.length);
    summary[label] = { avg_in_ms, std_dev };
}
const csvLines = Object.entries(summary).map(([step, stats]) => {
    const avg = stats.avg_in_ms.toFixed(6);
    const std = stats.std_dev.toFixed(6);
    return `${n_issuers},${step},${avg},${std}`;
});
fs.appendFileSync(RESULTS_CSV, csvLines.join('\n') + '\n');
console.log(`\n[Standard Veramo] Results for ${n_issuers} issuers`);
console.table(summary);
await cleanup();
