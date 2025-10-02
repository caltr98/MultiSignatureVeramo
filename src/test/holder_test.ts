import {
    IMessage,
    VerifiableCredential,
    VerifiablePresentation,
} from '@veramo/core'
import { PresentationPayload } from '@veramo/core-types'
import { agent } from '../veramo/setup.js'
import { performance } from 'node:perf_hooks'

// NOTE: keep payload parity with multi_issuer VC flow
// Canonical VP payload fields (exactly these, in this order when canonicalized):
//  - @context: ["https://www.w3.org/2018/credentials/v1","https://www.w3.org/ns/credentials/v2"]
//  - type: ["VerifiablePresentation"]
//  - multi_holders: string[]
//  - verifiableCredential: [VC]
//  - aggregated_bls_public_key: string

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

/** Holder descriptor (mirrors issuer struct shape) */
export interface HolderInfo {
    did: string
    kid_bls: string
}

/** Store VC as message (unchanged) */
export async function storeCredential(vc: VerifiableCredential): Promise<string> {
    const stored = await agent.dataStoreSaveMessage({
        message: {
            type: 'multi-issuer-vc',
            data: vc,
            createdAt: new Date().toISOString(),
        } as IMessage,
    })
    return stored
}

/** ---- helpers aligned with issuer_test ---- */

async function getBlsKeyHex(kid: string): Promise<string> {
    const key = await agent.keyManagerGet({ kid })
    return key.publicKeyHex
}

async function aggregateBlsKeys(keys: string[]): Promise<string> {
    return (await agent.aggregateBlsPublicKeys({ list_of_publicKeyHex: keys }))
        .bls_aggregated_pubkey as string
}

async function getAndAggregateBlsKeysForHolders(holders: HolderInfo[]): Promise<string> {
    const keysHex = await Promise.all(holders.map(h => getBlsKeyHex(h.kid_bls)))
    return aggregateBlsKeys(keysHex)
}

async function getEthKeyKidForDid(did: string): Promise<string> {
    const identifier = await agent.didManagerGet({ did })
    const ethKey = identifier.keys.find(
        (k) => k.type === 'Secp256k1' || k.meta?.alg === 'eth_signMessage'
    )
    if (!ethKey) throw new Error(`No Ethereum-compatible key found for DID ${did}`)
    return ethKey.kid
}

/** Build VP payload INCLUDING aggregated key (must be present for signing & verify) */
function buildVPPayloadWithAggKey(
    holderDids: string[],
    aggregatedKey: string,
    vc?: VerifiableCredential
): PresentationPayload & { multi_holders: string[]; aggregated_bls_public_key: string } {
    return {
        '@context': ['https://www.w3.org/2018/credentials/v1', 'https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiablePresentation'],
        multi_holders: holderDids,
        verifiableCredential: [vc],
        aggregated_bls_public_key: aggregatedKey,
    } as any
}

/** Collect BLS partials from all holders (payload includes aggregated_bls_public_key) */
async function collectPartialVPSignatures(
    presentation: PresentationPayload & { multi_holders: string[]; aggregated_bls_public_key: string },
    holders: HolderInfo[]
): Promise<{ signatures: string[]; payloadToSign: string }> {
    const signatures: string[] = []
    let payloadToSign = ''
    for (const h of holders) {
        const partial = await agent.signMultiHolderVerifiablePresentation({
            presentation,
            holder: h.did,
            keyRef: h.kid_bls,
            proofFormat: 'sign-bls-multi-signature-vp',
        } as any)
        if (!payloadToSign) payloadToSign = partial.signatureData.payloadToSign
        signatures.push(partial.signatureData.signatureHex)
    }
    return { signatures, payloadToSign }
}

/** Create PoOs for each holder over the exact canonical payload-to-sign */
async function
createPoOsForHolders(holderDids: string[], payloadToSign: string): Promise<string[]> {
    // payloadToSign is already the canonicalized JSON string from the signer – do NOT re-canonicalize or stringify
    const proofs: string[] = []
    console.log("payloadToSign: "+JSON.stringify(payloadToSign))
    for (const did of holderDids) {
        const kidEth = await getEthKeyKidForDid(did)
        const sig = await agent.keyManagerSign({
            keyRef: kidEth,
            data: payloadToSign,
            algorithm: 'eth_signMessage',
            encoding: 'utf-8',
        })
        proofs.push(sig)
    }
    return proofs
}

/**
 * Create a multi-holder VP with aggregated BLS signature.
 * - holders: array of { did, kid_bls }
 * - usePoO: also attach Proofs-of-Ownership and use PoO+agg VP method
 * - aggregatedKey (optional): pass the key computed in issuer_test to keep strict parity
 */
export async function createMultiHolderPresentation(
    holders: HolderInfo[],
    usePoO = true,
    timings?: BenchmarkResults,
    aggregatedKey?: string,
    vc?: VerifiableCredential,
    attributes?: Record<string, any>
): Promise<VerifiablePresentation> {
    const holderDids = holders.map(h => h.did)

    const aggKey = aggregatedKey ?? (
        timings
            ? await benchmarkStep('VP: aggregate holders BLS keys', timings, async () =>
                getAndAggregateBlsKeysForHolders(holders)
            )
            : await getAndAggregateBlsKeysForHolders(holders)
    )

    // payload that includes the aggregated key
    const basePresentationCore = buildVPPayloadWithAggKey(holderDids, aggKey,vc)

    // <-- NEW: attach attributes if provided
    const basePresentation = attributes !== undefined
        ? { ...basePresentationCore, attributes }
        : basePresentationCore

    // collect partials
    const { signatures, payloadToSign } = timings
        ? await benchmarkStep('VP: collect partial signatures', timings, async () =>
            collectPartialVPSignatures(basePresentation, holders)
        )
        : await collectPartialVPSignatures(basePresentation, holders)

    if (usePoO) {
        const proofsOfOwnership = timings
            ? await benchmarkStep('VP: generate PoOs', timings, async () =>
                createPoOsForHolders(holderDids, payloadToSign)
            )
            : await createPoOsForHolders(holderDids, payloadToSign)

        // assemble PoO + aggregated BLS VP
        return timings
            ? await benchmarkStep('VP: assemble (PoO+BLS agg)', timings, async () =>
                agent.createProofOfOwnershipMultiHolderVerifiablePresentation({
                    presentation: basePresentation,
                    signatures,
                    proofsOfOwnership,
                    proofFormat: 'ProofOfOwnership-aggregate-bls-multi-signature-vp',
                } as any)
            )
            : await agent.createProofOfOwnershipMultiHolderVerifiablePresentation({
                presentation: basePresentation,
                signatures,
                proofsOfOwnership,
                proofFormat: 'ProofOfOwnership-aggregate-bls-multi-signature-vp',
            } as any)
    }

    // assemble BLS-aggregated VP (no PoO)
    return timings
        ? await benchmarkStep('VP: assemble (BLS agg)', timings, async () =>
            agent.createMultiHolderVerifiablePresentation({
                presentation: basePresentation,
                signatures,
                proofFormat: 'aggregate-bls-multi-signature-vp',
            } as any)
        )
        : await agent.createMultiHolderVerifiablePresentation({
            presentation: basePresentation,
            signatures,
            proofFormat: 'aggregate-bls-multi-signature-vp',
        } as any)
}

//** Single-holder VP helper (renamed from createPresentation) */
export async function createSingleHolderPresentation(
    vc: VerifiableCredential,
    holderDid: string,
): Promise<VerifiablePresentation> {
    const presentationPayload: PresentationPayload = {
        '@context': ['https://www.w3.org/2018/credentials/v1', 'https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiablePresentation'],
        holder: holderDid,
        verifiableCredential: [vc],
    }
    return agent.createVerifiablePresentation({
        presentation: presentationPayload,
        proofFormat: 'jwt',
    })
}
