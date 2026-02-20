import {cleanup, setup_bls_agents} from "./enviroment_setup.js";
import {generateVCPayload} from "./generate_VC_payload.js";
import {
    generatePayloadToSign,
    getBlsKeyHex,
    VCAggregateKeysToSignatures,
    VCAggregateKeysToSignaturesWithBenchmark
} from "./issuers_test.js";
import {createAgent, IMessage, PresentationPayload} from "@veramo/core";
import {agent} from "../veramo/setup.js";
const claims_n = 2
const claims_size = 14
import {VerifiableCredential, VerifiablePresentation} from "@veramo/core-types";
import {createSingleHolderPresentation, storeCredential} from "./holder_test.js";
import {verifyMultiSignatureVC, verifyVP} from "./verifier_test.js";

type BenchmarkResults = Record<string, number>

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
//create all agents for issuer, holder, and verifier
//50 issuer is a NO-GO when using INFURA!
const issuers = await setup_bls_agents(2);

const holder = (await setup_bls_agents(1))[0];


const verifier = (await setup_bls_agents(1))[0];
//
//-----

await getBlsKeyHex(issuers[0].kid_bls)


let res =  (await VCAggregateKeysToSignaturesWithBenchmark(issuers, holder.did, claims_n, claims_size));
let VC = res.vc as VerifiableCredential

const timings: BenchmarkResults = {}
console.log("VC Aggregate Keys to Signatures"+JSON.stringify(VC,null,2))
Object.assign(timings, res.timings)

//let VC =  (await VCAggregateKeysToSignatures(issuers, holder.did, claims_n, claims_size)) as VerifiableCredential;


// --- Store VC (Holder) ---
await benchmarkStep('Store VC', timings, async () => {
    return storeCredential(VC)
})


let vp:any;
// --- Create VP (Holder) ---
await benchmarkStep('Create VP', timings, async () => {
    vp = await createSingleHolderPresentation(VC, holder.did)
    return vp
})


console.log("VP"+JSON.stringify(vp,null,2))

// --- Verify VP (Verifier) ---
await benchmarkStep('Verify VP', timings, async () => {
    return verifyVP( vp)
})


let verified = false;
let lastResult;

while (!verified) {
    lastResult = await benchmarkStep('Verify MultiSig VC', timings, async () => {
        const res = await verifyMultiSignatureVC(VC);
        return res;
    });

    if (lastResult?.verified) {
        verified = true;
    } else {
        console.log('Verification failed, repeating benchmark...');
    }
}

// --- Results ---
console.table(timings)


//cleanup all agents


/*
await missOneSignatureVCAggregateKeysToSignatures(issuers, holder.did, claims_n, claims_size)
await ChangePayloadSignatureVCAggregateKeysToSignatures(issuers, holder.did, claims_n, claims_size)
await wrongPayloadInProofOfOwnership(issuers, holder.did, claims_n, claims_size)
*/


await cleanup()

