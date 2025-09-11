    import {cleanup, setup_bls_agents} from "./enviroment_setup.js";
    import {generateVCPayload} from "./generate_VC_payload";
    import {
        generatePayloadToSign,
        getBlsKeyHex,
        VCAggregateKeysToSignatures,
        VCAggregateKeysToSignaturesWithBenchmark
    } from "./issuers_test.js";
    import fs from 'fs';
    import path from 'path';

    // Path of the CSV file where results will be appended
    const RESULTS_CSV = path.resolve('./benchmark_results.csv');

    // Write CSV header if file does not exist yet
    if (!fs.existsSync(RESULTS_CSV)) {
        const header = 'Issuers,StepName,avg_ms,std_ms\n';
        fs.writeFileSync(RESULTS_CSV, header);
    }

    //run with yarn ts-node --esm ./src/test/full_test_main.js --claims 40 --size 2048 --issuers 8 --runs 5
    function parseArg(name: string, defaultValue: number): number {
        const index = process.argv.indexOf(`--${name}`)
        if (index !== -1 && process.argv[index + 1]) {
            const val = parseInt(process.argv[index + 1])
            if (!isNaN(val)) return val
        }
        return defaultValue
    }

    // Parse command-line inputs with defaults
    const claims_n = parseArg('claims', 32)
    const claims_size = parseArg('size', 1024)
    const n_issuers = parseArg('issuers', 12)
    const RUNS = parseArg('runs', 10)


    import {VerifiableCredential, VerifiablePresentation} from "@veramo/core-types";
    import {createPresentation, storeCredential} from "./holder_test.js";
    import {verifyMultiSignatureVC, verifyVP} from "./verifier_test.js";

    type BenchmarkResults = Record<string, number>
    function sleep(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms))
    }

    export async function benchmarkStep<T>(
        label: string,
        results: BenchmarkResults,
        fn: () => Promise<T>
    ): Promise<T> {
        const start = performance.now()
        const result = await fn()
        const end = performance.now()
        results[label] = end - start
        return result
    }

    import {missOneSignatureVCAggregateKeysToSignatures} from "./securityCases/missingOneSignature.js";
    import {ChangePayloadSignatureVCAggregateKeysToSignatures} from "./securityCases/changingThePayload.js";
    import {wrongPayloadInProofOfOwnership} from "./securityCases/wrongPayloadInProofOfOwnership.js";
    import {performance} from "node:perf_hooks";
    import canonicalize from "canonicalize";
    import bls from "@chainsafe/bls";
    import {hexToBytes} from "@veramo/utils";
    //create all agents for issuer, holder, and verifier
    //50 issuer is a NO-GO when using INFURA!
    const issuers = await setup_bls_agents(n_issuers);

    const holder = (await setup_bls_agents(1))[0];

    //
    //-----

    await getBlsKeyHex(issuers[0].kid_bls)

    const allTimings: Record<string, number[]> = {}

    for (let i = 0; i < RUNS; i++) {
        console.log(`\n Run ${i + 1} of ${RUNS}`)

        const timings: BenchmarkResults = {}

        const res = await VCAggregateKeysToSignaturesWithBenchmark(
            issuers,
            holder.did,
            claims_n,
            claims_size
        )
        const VC = res.vc as VerifiableCredential

        Object.assign(timings, res.timings)

        await benchmarkStep('Store VC', timings, () => storeCredential(VC))
        let vp:any;
        await benchmarkStep('Create VP', timings, async () => {
            vp = await createPresentation(VC, holder.did);
            return vp;
        });

        // --- Verify VP (Verifier) ---
        await benchmarkStep('Verify VP', timings, async () => {
            return verifyVP(vp as VerifiablePresentation);
        });


        let verified = false;
        let lastResult: any;


        while (!verified) {
            const res = await verifyMultiSignatureVC(VC);
            // Include internal substep timings (e.g., BLS, DID resolution, PoO)
            if (res.timings) {
                    for (const [label, time] of Object.entries(res.timings)) {
                        timings[label] = time as number;
                    }
                }

            if (res?.verified) {
                verified = true;
            } else {
                console.log('Verification failed, repeating benchmark...');
                await sleep(3000);
            }
        }
        // Accumulate
        for (const [label, value] of Object.entries(timings)) {
            if (!allTimings[label]) {
                allTimings[label] = []
            }
            allTimings[label].push(value)
        }
        await sleep(100) // cooldown for alchemy!
    }

    // Compute averages
    const summary: Record<string, { avg_in_ms: number; std_dev: number }> = {}
    for (const [label, values] of Object.entries(allTimings)) {
        const avg_in_ms = values.reduce((a, b) => a + b, 0) / values.length
        const std_dev = Math.sqrt(
            values.reduce((sum, x) => sum + Math.pow(x - avg_in_ms, 2), 0) / values.length
        )
        summary[label] = { avg_in_ms, std_dev }
    }

    // Prepare CSV lines for this run
    const csvLines: string[] = [];
    for (const [step, stats] of Object.entries(summary)) {
        const avg = stats.avg_in_ms.toFixed(6);  // adjust decimals as needed
        const std = stats.std_dev.toFixed(6);
        csvLines.push(`${n_issuers},${step},${avg},${std}`);
    }

    // Append all lines to CSV file
    fs.appendFileSync(RESULTS_CSV, csvLines.join('\n') + '\n');
    console.log(`Appended results for ${n_issuers} issuers to ${RESULTS_CSV}`);

    // Print result
    console.log(`\nAverage timings and standard deviation with ${claims_n} claims of ${claims_size}, ${n_issuers} issuers, and ${RUNS} runs:`)
    console.log(`Average timings and standard deviation over ${RUNS} runs:`)
    console.table(summary)


    await cleanup()


