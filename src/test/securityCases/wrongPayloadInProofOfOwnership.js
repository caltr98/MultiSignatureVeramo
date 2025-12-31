import { agent } from '../../veramo/setup.js';
import bls from "@chainsafe/bls";
import { getAndAggregateBlsKeys, generatePayloadToSign, signPayloadWithIssuers, createProofsOfOwnershipPerIssuer } from "../issuers_test.js";
export async function wrongPayloadInProofOfOwnership(issuers, holder, claimCount, valueSize, seed = 42) {
    const aggregateBlsKeys = await getAndAggregateBlsKeys(issuers);
    // 1. Generate deterministic payload
    const payload = await generatePayloadToSign(issuers, holder, aggregateBlsKeys, claimCount, valueSize, seed);
    const payloadString = payload.toString();
    // 2. BLS Signatures from all issuers
    const signaturesHexAndSignatures = await signPayloadWithIssuers(payload, issuers);
    const signaturesHex = signaturesHexAndSignatures.signatures;
    const signaturesPayloadSigned = signaturesHexAndSignatures.payloads;
    // 3. Aggregate BLS signatures
    const signatureObjs = signaturesHex.map(sigHex => bls.Signature.fromHex(sigHex));
    const aggregatedSignature = bls.aggregateSignatures(signatureObjs);
    // 4. DEBUG TEST Verify aggregated signature using verifyAggregate
    //const pubKeys = await Promise.all(issuers.map(i => bls.PublicKey.fromBytes(Buffer.from(i.bls_pub_key,"hex"))))
    //debug test
    //const isValidAgg = bls.verifyAggregate(pubKeys, Uint8Array.from(Buffer.from(signaturesPayloadSigned[0], 'utf-8')), aggregatedSignature)
    // 5. PoO (Proofs of Ownership)
    //NEW:WRONG PAYLOAD
    const payload2 = await generatePayloadToSign(issuers, holder, aggregateBlsKeys, claimCount, valueSize, seed + 1);
    const proofsOfOwnership = await createProofsOfOwnershipPerIssuer(issuers, holder, payload2);
    // 6. VC with embedded BLS aggregate proof and PoOs
    const vcFull = await agent.createProofOfOwnershipMultiIssuerVerifiableCredential({
        credential: payload,
        proofData: {
            signatures: signaturesHex,
            publicKey: aggregateBlsKeys
        },
        type: ['Sign_MultiSign_VerifiableCredential'],
        proofsOfOwnership,
        proofFormat: 'ProofOfOwnership-aggregate-bls-multi-signature',
        signatures: signaturesHex
    });
    //FOR DEBUG
    // 7. Veramo-level credential verification
    const result = await agent.verifyProofOfOwnershipMultisignatureCredential({
        credential: {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            type: ["VerifiableCredential", "aggregated-bls-multi-signature"],
            multi_issuers: vcFull.multi_issuers,
            credentialSubject: vcFull.credentialSubject,
            proof: vcFull.proof,
            aggregated_bls_public_key: vcFull.aggregated_bls_public_key,
        }
    });
    console.log("wrong payload in proof of ownership verification result: " + JSON.stringify(result));
    return vcFull;
}
