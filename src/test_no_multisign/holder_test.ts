import {
    IAgent,
    IMessage,
    VerifiableCredential,
    VerifiablePresentation,
} from '@veramo/core'

import { PresentationPayload } from '@veramo/core-types'
import {agent} from "../veramo/setup.js";

/**
 * Store a Verifiable Credential as a message in the Veramo DataStore.
 * @param vc The Verifiable Credential to store.
 * @param agent The Veramo agent.
 * @returns The message ID (hash) of the stored message.
 */
export async function storeCredential(
    vc: VerifiableCredential,
): Promise<string> {
    const stored = await agent.dataStoreSaveMessage({
        message: {
            type: 'multi-issuer-vc',
            data: vc,
            createdAt: new Date().toISOString(),
        } as IMessage,
    })

    //console.log('Credential stored with message ID:', stored)
    return stored
}

/**
 * Create a Verifiable Presentation from a given Verifiable Credential.
 * @param vc The Verifiable Credential to present.
 * @param holderDid The DID of the holder.
 * @returns A Verifiable Presentation object.
 */
export async function createPresentation(
    vcs: VerifiableCredential[],
    holderDid: string,
): Promise<VerifiablePresentation> {
    const presentationPayload: PresentationPayload = {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiablePresentation'],
        holder: holderDid,
        verifiableCredential:vcs,
    }

    const vp = await agent.createVerifiablePresentation({
        presentation: presentationPayload,
        proofFormat: 'jwt',
    })
    return vp
}




