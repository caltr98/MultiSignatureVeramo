import { agent } from '../../veramo/setup.js';
import canonicalize from 'canonicalize';
/** Store VC */
export async function storeCredential(vc) {
    const stored = await agent.dataStoreSaveVerifiableCredential({
        verifiableCredential: vc,
    });
    return stored;
}
/** Store VC as message (unchanged) */
export async function storeMultiIssuerCredential(vc) {
    const stored = await agent.dataStoreSaveMessage({
        message: {
            type: 'multi-issuer-vc',
            data: vc,
            createdAt: new Date().toISOString(),
        },
    });
    return stored;
}
async function getBlsKeyHex(kid) {
    const key = await agent.keyManagerGet({ kid });
    return key.publicKeyHex;
}
export async function aggregateBlsKeys(keys) {
    return (await agent.aggregateBlsPublicKeys({ list_of_publicKeyHex: keys })).bls_aggregated_pubkey;
}
async function getAndAggregateBlsKeysForHolders(holders) {
    const keysHex = await Promise.all(holders.map((h) => getBlsKeyHex(h.kid_bls)));
    return aggregateBlsKeys(keysHex);
}
/** Build VP payload INCLUDING aggregated key (must be present for signing & verify) */
export function buildVPPayloadWithAggKey(holderDids, aggregatedKey, vcs, attributes) {
    return {
        '@context': ['https://www.w3.org/2018/credentials/v1', 'https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiablePresentation'],
        multi_holders: holderDids,
        ...(attributes ? { attributes } : {}),
        verifiableCredential: vcs ? vcs : [],
        aggregated_bls_public_key: aggregatedKey,
    };
}
/** Create individual BLS signature by holder (payload includes aggregated_bls_public_key) */
export async function IndividualBlsVPSignatures(presentation, mydid, mykidbls) {
    const result = await agent.signMultiHolderVerifiablePresentation({
        presentation,
        holder: mydid,
        keyRef: mykidbls,
        proofFormat: 'sign-bls-multi-signature-vp',
    });
    return {
        signature: result.signatureData.signatureHex,
        payloadToSign: result.signatureData.payloadToSign,
    };
}
/** Create PoO holder over the exact canonical payload-to-sign */
export async function createPoO(mydid, mykidEth, payloadToSign) {
    const payload = canonicalize(payloadToSign);
    const sig = await agent.keyManagerSign({
        keyRef: mykidEth,
        data: JSON.stringify(payload),
        algorithm: 'eth_signMessage',
        encoding: 'utf-8',
    });
    return sig;
}
/**
 * Create a multi-holder Verifiable Presentation (VP) with aggregated BLS signature (+PoO).
 */
export async function createMultiHolderPresentation(holders, usePoO = true, aggregatedKey, blssignatures, proofsofownership, payload) {
    const basePresentationCore = payload;
    const basePresentation = basePresentationCore;
    if (usePoO) {
        return agent.createProofOfOwnershipMultiHolderVerifiablePresentation({
            presentation: basePresentation,
            signatures: blssignatures,
            proofsOfOwnership: proofsofownership,
            proofFormat: 'ProofOfOwnership-aggregate-bls-multi-signature-vp',
        });
    }
    return agent.createMultiHolderVerifiablePresentation({
        presentation: basePresentation,
        signatures: blssignatures,
        proofFormat: 'aggregate-bls-multi-signature-vp',
    });
}
/** Create a single-holder VP containing ALL stored credentials. */
export async function createSingleHolderPresentationFromStoredVCs(holderDid, proofFormat = 'jwt') {
    const rows = await agent.dataStoreORMGetVerifiableCredentials({
        where: [{ column: 'subject', value: [holderDid] }],
    });
    const vcs = rows.map((r) => r.verifiableCredential);
    const presentationPayload = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiablePresentation'],
        holder: holderDid,
        verifiableCredential: vcs,
    };
    return agent.createVerifiablePresentation({
        presentation: presentationPayload,
        proofFormat,
    });
}
