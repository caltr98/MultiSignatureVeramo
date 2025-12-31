import { IMessage, VerifiableCredential, VerifiablePresentation } from '@veramo/core'
import { PresentationPayload } from '@veramo/core-types'
import { agent } from '../../veramo/setup.js'
import canonicalize from 'canonicalize'

/** Holder descriptor (mirrors issuer struct shape) */
export interface HolderInfo {
  did: string
  kid_bls: string
}

/** Store VC */
export async function storeCredential(vc: VerifiableCredential): Promise<string> {
  const stored = await agent.dataStoreSaveVerifiableCredential({
    verifiableCredential: vc,
  })
  return stored
}

/** Store VC as message (unchanged) */
export async function storeMultiIssuerCredential(vc: VerifiableCredential): Promise<string> {
  const stored = await agent.dataStoreSaveMessage({
    message: {
      type: 'multi-issuer-vc',
      data: vc,
      createdAt: new Date().toISOString(),
    } as IMessage,
  })
  return stored
}

async function getBlsKeyHex(kid: string): Promise<string> {
  const key = await agent.keyManagerGet({ kid })
  return key.publicKeyHex
}

export async function aggregateBlsKeys(keys: string[]): Promise<string> {
  return (await agent.aggregateBlsPublicKeys({ list_of_publicKeyHex: keys })).bls_aggregated_pubkey as string
}

async function getAndAggregateBlsKeysForHolders(holders: HolderInfo[]): Promise<string> {
  const keysHex = await Promise.all(holders.map((h) => getBlsKeyHex(h.kid_bls)))
  return aggregateBlsKeys(keysHex)
}

/** Build VP payload INCLUDING aggregated key (must be present for signing & verify) */
export function buildVPPayloadWithAggKey(
  holderDids: string[],
  aggregatedKey: string,
  vcs?: VerifiableCredential[],
  attributes?: Record<string, any>,
): PresentationPayload & { multi_holders: string[]; aggregated_bls_public_key: string } {
  return {
    '@context': ['https://www.w3.org/2018/credentials/v1', 'https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiablePresentation'],
    multi_holders: holderDids,
    ...(attributes ? { attributes } : {}),
    verifiableCredential: vcs ? vcs : [],
    aggregated_bls_public_key: aggregatedKey,
  } as any
}

/** Create individual BLS signature by holder (payload includes aggregated_bls_public_key) */
export async function IndividualBlsVPSignatures(
  presentation: PresentationPayload & { multi_holders: string[]; aggregated_bls_public_key: string },
  mydid: string,
  mykidbls: string,
): Promise<{ signature: string; payloadToSign: string }> {
  const result = await agent.signMultiHolderVerifiablePresentation({
    presentation,
    holder: mydid,
    keyRef: mykidbls,
    proofFormat: 'sign-bls-multi-signature-vp',
  } as any)

  return {
    signature: result.signatureData.signatureHex,
    payloadToSign: result.signatureData.payloadToSign,
  }
}

/** Create PoO holder over the exact canonical payload-to-sign */
export async function createPoO(mydid: string, mykidEth: string, payloadToSign: string): Promise<string> {
  const payload = canonicalize(payloadToSign)
  const sig = await agent.keyManagerSign({
    keyRef: mykidEth,
    data: JSON.stringify(payload),
    algorithm: 'eth_signMessage',
    encoding: 'utf-8',
  })
  return sig
}

/**
 * Create a multi-holder Verifiable Presentation (VP) with aggregated BLS signature (+PoO).
 */
export async function createMultiHolderPresentation(
  holders: string[],
  usePoO = true,
  aggregatedKey: string,
  blssignatures: string[],
  proofsofownership: string[],
  payload: object,
): Promise<VerifiablePresentation> {
  const basePresentationCore = payload as PresentationPayload & {
    multi_holders: string[]
    aggregated_bls_public_key: string
  }
  const basePresentation = basePresentationCore

  if (usePoO) {
    return agent.createProofOfOwnershipMultiHolderVerifiablePresentation({
      presentation: basePresentation,
      signatures: blssignatures,
      proofsOfOwnership: proofsofownership,
      proofFormat: 'ProofOfOwnership-aggregate-bls-multi-signature-vp',
    } as any)
  }

  return agent.createMultiHolderVerifiablePresentation({
    presentation: basePresentation,
    signatures: blssignatures,
    proofFormat: 'aggregate-bls-multi-signature-vp',
  } as any)
}

/** Create a single-holder VP containing ALL stored credentials. */
export async function createSingleHolderPresentationFromStoredVCs(
  holderDid: string,
  proofFormat: 'jwt' | 'lds' = 'jwt',
): Promise<VerifiablePresentation> {
  const rows = await agent.dataStoreORMGetVerifiableCredentials({
    where: [{ column: 'subject', value: [holderDid] }],
  })

  const vcs = rows.map((r) => r.verifiableCredential as VerifiableCredential)

  const presentationPayload: PresentationPayload = {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiablePresentation'],
    holder: holderDid,
    verifiableCredential: vcs,
  }

  return agent.createVerifiablePresentation({
    presentation: presentationPayload,
    proofFormat,
  })
}

