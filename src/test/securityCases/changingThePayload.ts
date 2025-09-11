import { agent } from '../../veramo/setup.js'
import bls from "@chainsafe/bls"
import { ethers } from 'ethers'

import { generateVCPayload } from "../generate_VC_payload.js"
import {
    ICreateProofOfOwnershipMultiIssuerVerifiableCredentialArgs,
    ISignMultiIssuerVerifiableCredentialArgs
} from "../../plugins/bls-extend-credential-w3c/src/action-handler"
import {MinimalImportableKey} from "@veramo/core-types";
import canonicalize from "canonicalize";
import {ProofType, UnsignedCredential} from "@veramo/core";

import {getAndAggregateBlsKeys,generatePayloadToSign,signPayloadWithIssuers, createProofsOfOwnershipPerIssuer } from "../issuers_test.js"

interface AgentInfo {
    did: string
    kid_bls: string
    bls_pub_key: string
}

async function ChangePayloadSignatureVCAggregateKeysToSignatures(
    issuers: AgentInfo[],
    holder: string,
    claimCount: number,
    valueSize: number,
    seed = 42
): Promise<UnsignedCredential & { proof: ProofType }> {
    const aggregateBlsKeys = await getAndAggregateBlsKeys(issuers)

    // 1. Generate deterministic payload
    const payload = await generatePayloadToSign(issuers, holder, aggregateBlsKeys, claimCount, valueSize, seed)
    const payloadString = payload.toString()

    // 2. BLS Signatures from all issuers
    let signaturesHexAndSignatures = await signPayloadWithIssuers(payload, issuers)

    let signaturesHex = signaturesHexAndSignatures.signatures as string[]
    let signaturesPayloadSigned = signaturesHexAndSignatures.payloads as string[]



    // 3. Aggregate BLS signatures
    const signatureObjs = signaturesHex.map(sigHex => bls.Signature.fromHex(sigHex))


    const aggregatedSignature = bls.aggregateSignatures(signatureObjs)


    // 4. DEBUG TEST Verify aggregated signature using verifyAggregate
    //const pubKeys = await Promise.all(issuers.map(i => bls.PublicKey.fromBytes(Buffer.from(i.bls_pub_key,"hex"))))


    //debug test
    //const isValidAgg = bls.verifyAggregate(pubKeys, Uint8Array.from(Buffer.from(signaturesPayloadSigned[0], 'utf-8')), aggregatedSignature)



    // 5. PoO (Proofs of Ownership)
    const proofsOfOwnership = await createProofsOfOwnershipPerIssuer(issuers, holder, payload)

    // NEW CHANGING THE PAYLOAD
    const payload2 = await generatePayloadToSign(issuers, holder, aggregateBlsKeys, claimCount, valueSize, 0)

    // 6. VC with embedded BLS aggregate proof and PoOs
    const vcFull = await agent.createProofOfOwnershipMultiIssuerVerifiableCredential({
        credential: payload2,
        proofData: {
            signatures: signaturesHex,
            publicKey: aggregateBlsKeys
        },
        type: ['Sign_MultiSign_VerifiableCredential'],
        proofsOfOwnership,
        proofFormat: 'ProofOfOwnership-aggregate-bls-multi-signature',
        signatures: signaturesHex
    } as ICreateProofOfOwnershipMultiIssuerVerifiableCredentialArgs & { proofFormat: 'ProofOfOwnership-aggregate-bls-multi-signature' })

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
    })

    console.log("changing the payload from the one signed result"+JSON.stringify(result))
    return vcFull;
}

export {
    ChangePayloadSignatureVCAggregateKeysToSignatures
}
