import canonicalizeLib from 'canonicalize'

const canonicalize = canonicalizeLib as unknown as (
  value: unknown,
) => string | undefined

export type BlsPayload = Record<string, unknown>
export type BlsSigner = {
  alg: string
  did: string
  signer: (data: Uint8Array) => Promise<string>
}

export function canonicalPayload(payload: BlsPayload): string {
  const encoded = canonicalize(payload)
  if (!encoded) throw new Error('Failed to canonicalize BLS payload')
  return encoded
}

function selectFields(document: BlsPayload, fields: string[]): BlsPayload {
  return Object.fromEntries(
    fields
      .filter((field) => document[field] !== undefined)
      .map((field) => [field, document[field]]),
  )
}

export function credentialPayload(
  document: BlsPayload,
  multi: boolean,
): BlsPayload {
  const fields = ['@context', 'type', 'credentialSubject']
  return selectFields(document, [
    ...fields,
    ...(multi
      ? ['multi_issuers', 'aggregated_bls_public_key']
      : ['issuer', 'issuanceDate']),
  ])
}

export function presentationPayload(
  document: BlsPayload,
  multi: boolean,
): BlsPayload {
  const fields = [
    '@context',
    'type',
    'verifiableCredential',
    'attributes',
    'challenge',
    'domain',
  ]
  return selectFields(document, [
    ...fields,
    ...(multi
      ? ['multi_holders', 'aggregated_bls_public_key']
      : ['holder', 'multi_holders', 'issuanceDate']),
  ])
}

export async function signPayload(payload: BlsPayload, options: BlsSigner) {
  const payloadToSign = canonicalPayload(payload)
  const signatureHex = await options.signer(
    new TextEncoder().encode(payloadToSign),
  )
  return { signatureData: { payloadToSign, signatureHex } }
}

export function requireSigners(value: unknown): string[] {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.some((did) => typeof did !== 'string' || !did.startsWith('did:'))
  ) {
    throw new Error('A non-empty array of signer DIDs is required')
  }
  if (new Set(value).size !== value.length)
    throw new Error('Duplicate signer DIDs are not allowed')
  return value
}

export function requireSignatures(
  value: unknown,
  signers: string[],
): asserts value is string[] {
  if (
    !Array.isArray(value) ||
    value.length !== signers.length ||
    value.some((signature) => typeof signature !== 'string' || !signature)
  ) {
    throw new Error('Exactly one signature is required for each signer')
  }
}
