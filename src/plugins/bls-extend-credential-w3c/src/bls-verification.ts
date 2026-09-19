import type {
  DIDResolutionOptions,
  IVerifyResult,
  VerifierAgentContext,
} from '@veramo/core-types'
import type { VerificationMethod } from 'did-resolver'
import { computeAddress, verifyMessage } from 'ethers'
import { BlsCrypto, type BlsBackend } from '@veramo-community/kms-local-bls'
import {
  canonicalPayload,
  requireSigners,
  requireSignatures,
  type BlsPayload,
} from './bls-payload.js'

type BlsProof = {
  type: string
  signatureValue: string
  verificationMethod: string | string[]
  ProofsOfOwnership?: string[]
}
type Verification = {
  payload: BlsPayload
  document: BlsPayload
  signers: unknown
  mode: 'single' | 'multi' | 'ownership'
  ownershipStringify?: boolean
}
type TimedResult = IVerifyResult & { timings?: Record<string, number> }

function readProof(document: BlsPayload, mode: Verification['mode']): BlsProof {
  const proof = document.proof as BlsProof | undefined
  const expected =
    mode === 'single'
      ? 'BlsSignaturePisa'
      : mode === 'multi'
        ? 'BlsMultiSignaturePisa'
        : 'ProofOfOwnershipBlsMultiSignaturePisa'
  if (
    !proof ||
    proof.type !== expected ||
    typeof proof.signatureValue !== 'string' ||
    !proof.signatureValue
  )
    throw new Error('Missing or malformed BLS proof')
  return proof
}

function verificationMethods(
  proof: BlsProof,
  signers: string[],
  mode: Verification['mode'],
): string[] {
  const methods =
    mode === 'single' ? [proof.verificationMethod] : proof.verificationMethod
  if (
    !Array.isArray(methods) ||
    methods.length !== signers.length ||
    methods.some(
      (method, index) =>
        typeof method !== 'string' || method.split('#')[0] !== signers[index],
    )
  ) {
    throw new Error(
      'Verification methods must match the signer roster in order',
    )
  }
  return methods as string[]
}

async function resolveMethod(
  method: string,
  type: string,
  context: VerifierAgentContext,
  options?: DIDResolutionOptions,
): Promise<VerificationMethod> {
  const result = await context.agent.resolveDid({ didUrl: method, options })
  const document = result.didDocument
  if (
    result.didResolutionMetadata.error ||
    !document ||
    document.id !== method.split('#')[0]
  )
    throw new Error(`Could not resolve ${method}`)
  const key = document.verificationMethod?.find(
    (entry) =>
      entry.type === type && (!method.includes('#') || entry.id === method),
  )
  if (!key || key.controller !== document.id)
    throw new Error(
      `Verification method ${method} is missing or has a different controller`,
    )
  return key
}

function ownershipAddress(method: VerificationMethod): string {
  const address =
    method.blockchainAccountId?.split(':').pop() ?? method.ethereumAddress
  if (typeof address === 'string' && /^0x[0-9a-f]{40}$/i.test(address))
    return address.toLowerCase()
  if (method.publicKeyHex)
    return computeAddress(
      `0x${method.publicKeyHex.replace(/^0x/, '')}`,
    ).toLowerCase()
  throw new Error(`No Ethereum verification key is available for ${method.id}`)
}

async function measure<T>(
  timings: Record<string, number>,
  name: string,
  operation: () => Promise<T>,
): Promise<T> {
  const start = performance.now()
  const value = await operation()
  timings[name] = performance.now() - start
  return value
}

async function verifyOwnership(
  request: Verification,
  proof: BlsProof,
  methods: string[],
  crypto: BlsCrypto,
  context: VerifierAgentContext,
  options: DIDResolutionOptions | undefined,
  timings: Record<string, number>,
): Promise<boolean> {
  const payload = canonicalPayload(request.payload)
  const valid = await measure(timings, 'BLS Signature Verification', () =>
    crypto.verify(
      request.document.aggregated_bls_public_key as string,
      new TextEncoder().encode(payload),
      proof.signatureValue,
    ),
  )
  if (!valid) return false
  const keys = await measure(timings, 'DID DocumentS Resolution', () =>
    Promise.all(
      methods.map((method) =>
        resolveMethod(
          method,
          'EcdsaSecp256k1RecoveryMethod2020',
          context,
          options,
        ),
      ),
    ),
  )
  const message = request.ownershipStringify ? JSON.stringify(payload) : payload
  return measure(timings, 'Proofs of Ownership Verification', async () =>
    keys.every(
      (key, index) =>
        verifyMessage(
          message,
          proof.ProofsOfOwnership![index],
        ).toLowerCase() === ownershipAddress(key),
    ),
  )
}

async function verifyResolved(
  payload: BlsPayload,
  proof: BlsProof,
  methods: string[],
  crypto: BlsCrypto,
  context: VerifierAgentContext,
  options?: DIDResolutionOptions,
): Promise<boolean> {
  const keys = await Promise.all(
    methods.map((method) =>
      resolveMethod(method, 'Bls12381G1', context, options),
    ),
  )
  const publicKeys = keys.map(blsPublicKey)
  const publicKey =
    publicKeys.length === 1
      ? publicKeys[0]
      : await crypto.aggregatePublicKeys(publicKeys)
  return crypto.verify(
    publicKey,
    new TextEncoder().encode(canonicalPayload(payload)),
    proof.signatureValue,
  )
}

function blsPublicKey(key: VerificationMethod): string {
  if (!key.publicKeyHex) throw new Error(`Missing BLS key for ${key.id}`)
  return key.publicKeyHex
}

function validateProof(request: Verification) {
  const proof = readProof(request.document, request.mode)
  const signers = requireSigners(request.signers)
  const methods = verificationMethods(proof, signers, request.mode)
  if (request.mode === 'ownership')
    requireSignatures(proof.ProofsOfOwnership, signers)
  return { proof, methods }
}

/** Malformed proofs fail through the same result contract as invalid signatures. */
export async function verifyBlsDocument(
  request: Verification,
  context: VerifierAgentContext,
  options?: DIDResolutionOptions,
  backend?: BlsBackend,
): Promise<TimedResult> {
  const timings = request.mode === 'ownership' ? {} : undefined
  try {
    const { proof, methods } = validateProof(request)
    const crypto = new BlsCrypto(backend)
    const verified =
      request.mode === 'ownership'
        ? await verifyOwnership(
            request,
            proof,
            methods,
            crypto,
            context,
            options,
            timings!,
          )
        : await verifyResolved(
            request.payload,
            proof,
            methods,
            crypto,
            context,
            options,
          )
    return verified
      ? { verified, ...(timings && { timings }) }
      : {
          verified,
          error: {
            message: 'BLS signature or ownership verification failed',
            errorCode: 'invalid_signature',
          },
          ...(timings && { timings }),
        }
  } catch (error) {
    return {
      verified: false,
      error: {
        message: error instanceof Error ? error.message : String(error),
        errorCode: 'verification_error',
      },
      ...(timings && { timings }),
    }
  }
}
