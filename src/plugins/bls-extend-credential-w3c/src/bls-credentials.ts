import type {
  DIDResolutionOptions,
  VerifiableCredential,
  VerifierAgentContext,
} from '@veramo/core-types'
import type { BlsBackend } from '@veramo-community/kms-local-bls'
import type {
  MultiIssuerVerifiableCredential,
  ProofOfOwnershipMultiIssuerVerifiableCredential,
} from './action-handler.js'
import {
  credentialPayload,
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

export async function createVerifiableCredentialBls(
  credential: BlsPayload,
  options: BlsSigner,
  _settings?: SignSettings,
): Promise<any> {
  const payload = credentialPayload(credential, false)
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

export async function signMultiSignatureVerifiableCredentialBls(
  credential: BlsPayload,
  options: BlsSigner,
  _settings?: SignSettings,
) {
  return signPayload(credentialPayload(credential, true), options)
}

export async function aggregateMultiSignatureVerifiableCredentialBls(
  credential: BlsPayload,
  options: BlsSigner,
  signatures: string[],
  _settings?: SignSettings,
): Promise<any> {
  return aggregateDocument(
    credential,
    credential.multi_issuers,
    signatures,
    options,
  )
}

export async function generateProofOfOwnershipMultiIssuerVerifiableCredentialBls(
  credential: BlsPayload,
  ownership: string[],
  signatures: string[],
  _settings?: string[],
  backend?: BlsBackend,
): Promise<any> {
  return aggregateOwnership(
    credential,
    credential.multi_issuers,
    signatures,
    ownership,
    backend,
  )
}

export async function verifyCredentialBls(
  credential: VerifiableCredential,
  context: VerifierAgentContext,
  resolutionOptions?: DIDResolutionOptions,
  backend?: BlsBackend,
) {
  const signer =
    typeof credential.issuer === 'string'
      ? credential.issuer
      : credential.issuer?.id
  return verifyBlsDocument(
    {
      document: credential,
      payload: credentialPayload(credential, false),
      signers: [signer],
      mode: 'single',
    },
    context,
    resolutionOptions,
    backend,
  )
}

export async function verifyCredentialMultiSignatureBls(
  credential: MultiIssuerVerifiableCredential,
  context: VerifierAgentContext,
  resolutionOptions?: DIDResolutionOptions,
  backend?: BlsBackend,
) {
  return verifyBlsDocument(
    {
      document: credential,
      payload: credentialPayload(credential, true),
      signers: credential.multi_issuers,
      mode: 'multi',
    },
    context,
    resolutionOptions,
    backend,
  )
}

export async function verifyCredentialProofOfOwnershipMultiSignatureBls(
  credential: ProofOfOwnershipMultiIssuerVerifiableCredential,
  context: VerifierAgentContext,
  resolutionOptions?: DIDResolutionOptions,
  backend?: BlsBackend,
) {
  return verifyBlsDocument(
    {
      document: credential,
      payload: credentialPayload(credential, true),
      signers: credential.multi_issuers,
      mode: 'ownership',
      ownershipStringify: true,
    },
    context,
    resolutionOptions,
    backend,
  )
}
