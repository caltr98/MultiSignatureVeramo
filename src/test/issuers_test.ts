import { agent } from '../veramo/setup.js'
import bls from "@chainsafe/bls"
import { ethers } from 'ethers'


import { performance } from 'node:perf_hooks'

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

import { generateVCPayload } from "./generate_VC_payload.js"
import {
    ICreateProofOfOwnershipMultiIssuerVerifiableCredentialArgs,
    ISignMultiIssuerVerifiableCredentialArgs
} from "../plugins/bls-extend-credential-w3c/src/action-handler"
import {MinimalImportableKey} from "@veramo/core-types";
import canonicalize from "canonicalize";
import {ProofType, UnsignedCredential} from "@veramo/core";

interface AgentInfo {
    did: string
    kid_bls: string
    bls_pub_key: string
}

async function getBlsPublicKey(kid: string) {
    const key = await agent.keyManagerGet({ kid })
    return bls.PublicKey.fromBytes(Buffer.from(key.publicKeyHex, 'hex'))
}


async function getBlsKeyHex(kid: string) {
    const key = await agent.keyManagerGet({ kid })
    return key.publicKeyHex
}

async function aggregateBlsKeys(keys: string[]):Promise<string> {
    return (await agent.aggregateBlsPublicKeys({ list_of_publicKeyHex: keys })).bls_aggregated_pubkey as string
}

export async function getAndAggregateBlsKeys(issuers: AgentInfo[]):Promise<string> {
    const keysHex = await Promise.all(issuers.map(issuer => getBlsKeyHex(issuer.kid_bls)))
    return await aggregateBlsKeys(keysHex)

}

async function getEthKeyKidForDid(did: string): Promise<string> {



    const identifier = await agent.didManagerGet({ did })
    const ethKey = identifier.keys.find(k =>
        k.type === 'Secp256k1' || k.meta?.alg === 'eth_signMessage'
    )
    if (!ethKey) throw new Error(`No Ethereum-compatible key found for DID ${did}`)
    return ethKey.kid
}

async function generatePayloadToSign(
    issuers: AgentInfo[],
    holder: string,
    aggregatedKey:  string ,
    claimCount: number,
    valueSize: number,
    seed = 42
): Promise<any> {
    return generateVCPayload({
        multiIssuers: issuers.map(i => i.did),
        holderDID: holder,
        aggregatedKey: aggregatedKey,
        claimCount,
        valueSize,
        seed
    })
}

export async function signPayloadWithIssuers(payload: string, issuers: AgentInfo[]): Promise<any> {
    const signatures: string[] = []
    const payloads: string[] = []
    for (const i of issuers) {
        const signature = await agent.signMultiIssuedVerifiableCredential({
            credential: payload,
            issuer: i.did,
            proofFormat: 'sign-bls-multi-signature',
            keyRef: i.kid_bls,
        } as ISignMultiIssuerVerifiableCredentialArgs & { proofFormat: 'sign-bls-multi-signature' })

        signatures.push(signature.signatureData.signatureHex)
        payloads.push(signature.signatureData.payloadToSign)

    }
    return ({signatures:signatures,payloads:payloads})
}

export async function createProofsOfOwnershipPerIssuer(
    issuers: AgentInfo[],
    holderDid: string,
    payload: string
): Promise<string[]> {
    const proofs: string[] = []
    for (const i of issuers) {
        let kid_eth = await getEthKeyKidForDid(i.did)
        let canonical = canonicalize(payload);
        const signature = await agent.keyManagerSign({keyRef: kid_eth, data: JSON.stringify(canonical),
            algorithm : "eth_signMessage", encoding: "utf-8" })
        proofs.push(signature)
    }
    return proofs
}

export async function createProofsOfPossessionPerIssuer(
    kid: string,
    nonce: string,
): Promise<string> {
    let messagePoP = getBlsPublicKey(kid)+""+nonce
    const PoP = await agent.keyManagerSign({keyRef: kid, data: messagePoP,
            algorithm : "BLS_SIGNATURE", encoding: "utf-8" })
    return PoP
}


export async function VCAggregateKeysToSignatures(
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

    const signaturesHexAndSignatures = await signPayloadWithIssuers(payload, issuers)
    const signaturesHex = signaturesHexAndSignatures.signatures as string[]
    const signaturesPayloadSigned = signaturesHexAndSignatures.payloads as string[]

    // 3. Aggregate BLS signatures
    const signatureObjs = signaturesHex.map(sigHex => bls.Signature.fromHex(sigHex))
    const aggregatedSignature = bls.aggregateSignatures(signatureObjs)


    // 4. DEBUG TEST Verify aggregated signature using verifyAggregate
    //const pubKeys = await Promise.all(issuers.map(i => bls.PublicKey.fromBytes(Buffer.from(i.bls_pub_key,"hex"))))


    //debug test
    //const isValidAgg = bls.verifyAggregate(pubKeys, Uint8Array.from(Buffer.from(signaturesPayloadSigned[0], 'utf-8')), aggregatedSignature)



    // 5. PoO (Proofs of Ownership)
    const proofsOfOwnership = await createProofsOfOwnershipPerIssuer(issuers, holder, payload)

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
    } as ICreateProofOfOwnershipMultiIssuerVerifiableCredentialArgs & { proofFormat: 'ProofOfOwnership-aggregate-bls-multi-signature' })

    //FOR DEBUG
    // 7. Veramo-level credential verification

    /*
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

    */
    return vcFull;
}

export {
    getBlsPublicKey,
    getBlsKeyHex,
    aggregateBlsKeys,
    generatePayloadToSign,

}

export async function VCAggregateKeysToSignaturesWithBenchmark(
    issuers: AgentInfo[],
    holder: string,
    claimCount: number,
    valueSize: number,
    seed = 42
): Promise<{ vc: UnsignedCredential & { proof: ProofType }, timings: Record<string, number> }> {
    const timings: Record<string, number> = {}


// Get BLS keys from wallet
    const keysHex = await Promise.all(issuers.map(issuer => getBlsKeyHex(issuer.kid_bls)))

    const aggregatedBlsKey = await benchmarkStep('Aggregate BLS keys', timings, async () => {
        return await aggregateBlsKeys(keysHex)
    })


    const payload = await benchmarkStep('Generate VC payload', timings, async () =>
        generatePayloadToSign(issuers, holder, aggregatedBlsKey, claimCount, valueSize, seed)
    )


    // Measure signing with all issuers and capture result + timing
    const signaturesHexAndSignatures = await benchmarkStep('Sign with N issuer', timings, async () => {
        return await signPayloadWithIssuers(payload, issuers);
    });


    const signaturesHex = signaturesHexAndSignatures.signatures as string[]
    const signaturesPayloadSigned = signaturesHexAndSignatures.payloads as string[]




    await benchmarkStep('Aggregate BLS signatures', timings, async () => {
        const signatureObjs = signaturesHex.map(sigHex => bls.Signature.fromHex(sigHex))
        bls.aggregateSignatures(signatureObjs)
    })

    // Measure generation of all PoOs
    const proofsOfOwnership = await benchmarkStep('Generate N PoOs', timings, async () => {
        return createProofsOfOwnershipPerIssuer(issuers, holder, payload);
    });


    const vc = await benchmarkStep('Create final VC', timings, async () =>
        agent.createProofOfOwnershipMultiIssuerVerifiableCredential({
            credential: payload,
            proofData: { signatures: signaturesHex, publicKey: aggregateBlsKeys },
            type: ['Sign_MultiSign_VerifiableCredential'],
            proofsOfOwnership,
            proofFormat: 'ProofOfOwnership-aggregate-bls-multi-signature',
            signatures: signaturesHex
        } as ICreateProofOfOwnershipMultiIssuerVerifiableCredentialArgs & {
            proofFormat: 'ProofOfOwnership-aggregate-bls-multi-signature'
        })
    )

    return { vc, timings }
}

function measure(obj: any): number {
    return Buffer.byteLength(JSON.stringify(obj), 'utf8');
}


export async function VCAggregateKeysToSignaturesWithSizes(
    issuers: AgentInfo[],
    holder: string,
    claimCount: number,
    valueSize: number,
    seed = 42
): Promise<{
    vc: UnsignedCredential & { proof: ProofType },
    sizes: Record<string, number>,
    intermediates: Record<string, any>
}> {
    const sizes: Record<string, number> = {};
    const intermediates: Record<string, any> = {};

    // Step 1: Get BLS keys
    const keysHex = await Promise.all(issuers.map(issuer => getBlsKeyHex(issuer.kid_bls)));
    const pk_bls = keysHex[0]; // sample size
    sizes['BLS pub key (1)'] = measure(pk_bls);
    sizes['BLS Key Exchange'] = issuers.length * (issuers.length - 1) * sizes['BLS pub key (1)'];

    // Step 2: Aggregate BLS keys
    const aggregatedBlsKey = await aggregateBlsKeys(keysHex);

    // Step 3: Generate payload (VC claims + metadata)
    const payload = await generatePayloadToSign(
        issuers,
        holder,
        aggregatedBlsKey,
        claimCount,
        valueSize,
        seed
    );
    intermediates['payload'] = payload;
    sizes['Claim Agreement'] = measure(payload) * issuers.length ** 2;

    // Step 4: Sign with all issuers
    const { signatures, payloads } = await signPayloadWithIssuers(payload, issuers);

    const signaturesHex = signatures as string[]

    intermediates['blsSignatures'] = signaturesHex as string[];
    sizes['Signature (1 BLS)'] = measure(signatures[0]);
    sizes['Sig to OIss'] = signatures.length * sizes['Signature (1 BLS)'];

    // Step 5: Aggregate BLS signatures
    const sigObjs = signaturesHex.map(sigHex => bls.Signature.fromHex(sigHex));
    const aggSig = bls.aggregateSignatures(sigObjs);
    intermediates['aggregatedBlsSig'] = aggSig;
    sizes['Aggregated BLS Signature'] = measure(aggSig);

    // Step 6: Generate PoOs
    const proofsOfOwnership = await createProofsOfOwnershipPerIssuer(issuers, holder, payload);
    intermediates['proofsOfOwnership'] = proofsOfOwnership;
    sizes['PoO (1)'] = measure(proofsOfOwnership[0]);
    sizes['PoOs to OIss'] = proofsOfOwnership.length * sizes['PoO (1)'];

    // Step 7: Create final VC
    const vc = await agent.createProofOfOwnershipMultiIssuerVerifiableCredential({
        credential: payload,
        proofData: { signatures, publicKey: aggregatedBlsKey },
        type: ['Sign_MultiSign_VerifiableCredential'],
        proofsOfOwnership,
        proofFormat: 'ProofOfOwnership-aggregate-bls-multi-signature',
        signatures
    } as ICreateProofOfOwnershipMultiIssuerVerifiableCredentialArgs & {
        proofFormat: 'ProofOfOwnership-aggregate-bls-multi-signature';
    });

    intermediates['finalVC'] = vc;
    sizes['VC to Holder'] = measure(vc);

    return { vc, sizes, intermediates };
}
