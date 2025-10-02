import {cleanup, setup_bls_agents} from "./enviroment_setup.js";
import {generateVCPayload} from "./generate_VC_payload";
import {
    generatePayloadToSign,
    getBlsKeyHex,
    VCAggregateKeysToSignatures,
    VCAggregateKeysToSignaturesWithBenchmark
} from "./issuers_test.js";
import {createAgent, IMessage, PresentationPayload} from "@veramo/core";
import {agent} from "../veramo/setup.js";
const claims_n = 4
const claims_size = 4
import {VerifiableCredential} from "@veramo/core-types";
import {createSingleHolderPresentation, storeCredential} from "./holder_test.js";
import {verifyMultiSignatureVC, verifyVP} from "./verifier_test.js";
import {missOneSignatureVCAggregateKeysToSignatures} from "./securityCases/missingOneSignature.js";
import {ChangePayloadSignatureVCAggregateKeysToSignatures} from "./securityCases/changingThePayload.js";
import {wrongPayloadInProofOfOwnership} from "./securityCases/wrongPayloadInProofOfOwnership.js";
//create all agents for issuer, holder, and verifier
//50 issuer is a NO-GO when using INFURA!
const issuers = await setup_bls_agents(10);

const holder = (await setup_bls_agents(1))[0];


const verifier = (await setup_bls_agents(1))[0];
//
//-----

await getBlsKeyHex(issuers[0].kid_bls)


let res =  (await VCAggregateKeysToSignaturesWithBenchmark(issuers, holder.did, claims_n, claims_size));
let VC = res.vc as VerifiableCredential
console.log(res.timings)
//let VC =  (await VCAggregateKeysToSignatures(issuers, holder.did, claims_n, claims_size)) as VerifiableCredential;

const storing = await storeCredential(VC)

const VP = await createSingleHolderPresentation(VC, holder.did)


let result = await verifyVP(VP)
console.log(result)
await verifyMultiSignatureVC(VC)



//cleanup all agents


/*
await missOneSignatureVCAggregateKeysToSignatures(issuers, holder.did, claims_n, claims_size)
await ChangePayloadSignatureVCAggregateKeysToSignatures(issuers, holder.did, claims_n, claims_size)
await wrongPayloadInProofOfOwnership(issuers, holder.did, claims_n, claims_size)
*/


await cleanup()


