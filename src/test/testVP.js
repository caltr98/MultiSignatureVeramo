// test_vp.ts
import { cleanup, setup_bls_agents } from './enviroment_setup.js';
import { getBlsKeyHex, VCAggregateKeysToSignaturesWithBenchmark, } from './issuers_test.js';
import { storeCredential, createMultiHolderPresentation, benchmarkStep, } from './holder_test.js'; // was './holder_test.js'
import { verifyMultiSignatureVP, verifyPoOVP, } from './verifier_test.js';
// --------- tweakables ----------
const ISSUERS_N = 2;
const HOLDERS_N = 2; // change number of holders here
const USE_POO = true; // set false for BLS-agg without PoO
const CLAIMS_N = 2;
const CLAIMS_SIZE = 14;
const timings = {};
async function main() {
    // --- agents ---
    const issuers = await setup_bls_agents(ISSUERS_N);
    const holdersRaw = await setup_bls_agents(HOLDERS_N);
    const holders = holdersRaw.map((h) => ({ did: h.did, kid_bls: h.kid_bls }));
    // touch a key (like your existing tests do)
    await getBlsKeyHex(issuers[0].kid_bls);
    // --- build VC (multi-issuer with BLS aggregate + optional PoO) ---
    let vcBuild = (await VCAggregateKeysToSignaturesWithBenchmark(issuers, holders[0].did, CLAIMS_N, CLAIMS_SIZE));
    const VC = vcBuild.vc;
    Object.assign(timings, vcBuild.timings);
    console.log('VC Aggregate Keys to Signatures', JSON.stringify(VC, null, 2));
    // --- store VC (holder) ---
    await benchmarkStep('Store VC', timings, async () => storeCredential(VC));
    // --- create multi-holder VP (holders sign BLS partials -> aggregate; optional PoO) ---
    let vp;
    await benchmarkStep(`Create VP (holders=${HOLDERS_N}, PoO=${USE_POO})`, timings, async () => {
        console.log("vc before multi holder", JSON.stringify(VC, null, 2));
        vp = (await createMultiHolderPresentation(holders, USE_POO, timings, undefined, undefined, { ciao: "ciao" }));
        return vp;
    });
    // --- verify VP ---
    if (USE_POO) {
        console.log("VP before very", JSON.stringify(vp, null, 2));
        await benchmarkStep('Verify VP (PoO + BLS agg)', timings, async () => {
            const res = await verifyPoOVP(vp);
            if (!res?.verified) {
                throw new Error(`VP PoO+BLS verification failed: ${JSON.stringify(res?.error ?? res)}`);
            }
            return res;
        });
    }
    else {
        await benchmarkStep('Verify VP (BLS agg only)', timings, async () => {
            const res = await verifyMultiSignatureVP(vp);
            if (!res?.verified) {
                throw new Error(`VP BLS verification failed: ${JSON.stringify(res?.error ?? res)}`);
            }
            return res;
        });
    }
    // --- results ---
    console.table(timings);
    await cleanup();
}
main().catch(async (e) => {
    console.error(e);
    try {
        await cleanup();
    }
    catch { }
    process.exit(1);
});
