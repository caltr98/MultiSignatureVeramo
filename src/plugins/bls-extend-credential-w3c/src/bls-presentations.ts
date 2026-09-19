import type {
  DIDResolutionOptions,
  VerifiablePresentation,
  VerifierAgentContext,
} from '@veramo/core-types'
import type { BlsBackend } from '@veramo-community/kms-local-bls'
import type {
  MultiIssuerVerifiablePresentation,
  ProofOfOwnershipMultiIssuerVerifiablePresentation,
} from './action-handler.js'
import {
  presentationPayload,
  signPayload,
  type BlsPayload,
  type BlsSigner,
} from './bls-payload.js'
import { aggregateDocument, aggregateOwnership } from './bls-aggregation.js'
import { verifyBlsDocument } from './bls-verification.js'

type SignSettings = {
  resolutionOptions?: DIDResolutionOptions & { publicKeyFormat?: string }
  fetchRemoteContexts?: boolean
}

export async function createVerifiablePresentationBls(
  presentation: BlsPayload,
  options: BlsSigner,
  _settings?: SignSettings,
): Promise<any> {
  const payload = presentationPayload(presentation, false)
  const { signatureData } = await signPayload(payload, options)
  return {
    ...payload,
    proof: {
      type: 'BlsSignaturePisa',
      created: new Date().toISOString(),
      proofPurpose: 'assertionMethod',
      verificationMethod: `${options.did}#delegate-1`,
      signatureValue: signatureData.signatureHex,
    },
  }
}

export async function signMultiSignatureVerifiablePresentationBls(
  presentation: BlsPayload,
  options: BlsSigner,
  _settings?: SignSettings,
) {
  return signPayload(presentationPayload(presentation, true), options)
}

export async function aggregateMultiSignatureVerifiablePresentationBls(
  presentation: BlsPayload,
  options: BlsSigner,
  signatures: string[],
  _settings?: SignSettings,
): Promise<any> {
  return aggregateDocument(
    presentation,
    presentation.multi_holders,
    signatures,
    options,
  )
}

export async function generateProofOfOwnershipMultiIssuerVerifiablePresentationBls(
  presentation: BlsPayload,
  ownership: string[],
  signatures: string[],
  _settings?: string[],
  backend?: BlsBackend,
): Promise<any> {
  return aggregateOwnership(
    presentation,
    presentation.multi_holders,
    signatures,
    ownership,
    backend,
  )
}

export async function verifyPresentationBls(
  presentation: VerifiablePresentation,
  context: VerifierAgentContext,
  resolutionOptions?: DIDResolutionOptions,
  backend?: BlsBackend,
) {
  const signer = presentation.holder
  return verifyBlsDocument(
    {
      document: presentation,
      payload: presentationPayload(presentation, false),
      signers: [signer],
      mode: 'single',
    },
    context,
    resolutionOptions,
    backend,
  )
}

export async function verifyPresentationMultiSignatureBls(
  presentation: MultiIssuerVerifiablePresentation,
  context: VerifierAgentContext,
  resolutionOptions?: DIDResolutionOptions,
  backend?: BlsBackend,
) {
  return verifyBlsDocument(
    {
      document: presentation,
      payload: presentationPayload(presentation, true),
      signers: presentation.multi_holders,
      mode: 'multi',
    },
    context,
    resolutionOptions,
    backend,
  )
}

export async function verifyPresentationProofOfOwnershipMultiSignatureBls(
  presentation: ProofOfOwnershipMultiIssuerVerifiablePresentation,
  context: VerifierAgentContext,
  resolutionOptions?: DIDResolutionOptions,
  backend?: BlsBackend,
) {
  return verifyBlsDocument(
    {
      document: presentation,
      payload: presentationPayload(presentation, true),
      signers: presentation.multi_holders,
      mode: 'ownership',
    },
    context,
    resolutionOptions,
    backend,
  )
}
