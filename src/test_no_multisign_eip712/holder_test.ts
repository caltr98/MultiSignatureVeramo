import { IMessage, VerifiableCredential, VerifiablePresentation } from '@veramo/core'
import { PresentationPayload } from '@veramo/core-types'
import { agent } from '../veramo/setup_eip712.js'

export async function storeCredential(vc: VerifiableCredential): Promise<string> {
  const stored = await agent.dataStoreSaveMessage({
    message: {
      type: 'single-issuer-vc',
      data: vc,
      createdAt: new Date().toISOString(),
    } as IMessage,
  })
  return stored
}

export async function createPresentation(
  vcs: VerifiableCredential[],
  holderDid: string,
  holderKeyRef?: string,
): Promise<VerifiablePresentation> {
  const presentationPayload: PresentationPayload = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiablePresentation'],
    holder: holderDid,
    verifiableCredential: vcs,
  }

  // Keep VP as JWT for simplicity; embedded VCs are verified separately.
  return agent.createVerifiablePresentation({
    presentation: presentationPayload,
    proofFormat: 'jwt',
    ...(holderKeyRef ? { keyRef: holderKeyRef } : {}),
  })
}
