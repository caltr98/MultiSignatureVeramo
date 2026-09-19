import { BlsCrypto, type BlsBackend } from '@veramo-community/kms-local-bls'
import {
  requireSigners,
  requireSignatures,
  type BlsPayload,
  type BlsSigner,
} from './bls-payload.js'

function proof(
  type: string,
  signers: string[],
  signatureValue: string,
  ownership?: string[],
) {
  return {
    type,
    proofPurpose: 'assertionMethod',
    verificationMethod: signers,
    signatureValue,
    ...(ownership && { ProofsOfOwnership: ownership }),
  }
}

export async function aggregateDocument(
  document: BlsPayload,
  roster: unknown,
  signatures: string[],
  signer: BlsSigner,
) {
  const signers = requireSigners(roster)
  requireSignatures(signatures, signers)
  const signature = await signer.signer(
    new TextEncoder().encode(JSON.stringify({ signatures })),
  )
  return {
    ...document,
    proof: {
      ...proof('BlsMultiSignaturePisa', signers, signature),
      created: new Date().toISOString(),
    },
  }
}

export async function aggregateOwnership(
  document: BlsPayload,
  roster: unknown,
  signatures: string[],
  ownership: string[],
  backend?: BlsBackend,
) {
  const signers = requireSigners(roster)
  requireSignatures(signatures, signers)
  requireSignatures(ownership, signers)
  const signature = await new BlsCrypto(backend).aggregateSignatures(signatures)
  return {
    ...document,
    issuanceDate: new Date().toISOString(),
    proof: proof(
      'ProofOfOwnershipBlsMultiSignaturePisa',
      signers,
      signature,
      ownership,
    ),
  }
}
