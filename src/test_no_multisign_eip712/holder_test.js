import { agent } from '../veramo/setup_eip712.js';
export async function storeCredential(vc) {
    const stored = await agent.dataStoreSaveMessage({
        message: {
            type: 'single-issuer-vc',
            data: vc,
            createdAt: new Date().toISOString(),
        },
    });
    return stored;
}
export async function createPresentation(vcs, holderDid, holderKeyRef) {
    const presentationPayload = {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiablePresentation'],
        holder: holderDid,
        verifiableCredential: vcs,
    };
    // Keep VP as JWT for simplicity; embedded VCs are verified separately.
    return agent.createVerifiablePresentation({
        presentation: presentationPayload,
        proofFormat: 'jwt',
        ...(holderKeyRef ? { keyRef: holderKeyRef } : {}),
    });
}
