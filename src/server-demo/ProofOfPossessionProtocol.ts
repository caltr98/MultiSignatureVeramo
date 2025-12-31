
import { agent } from '../veramo/setup.js'
import { bytesToHex, hexToBytes } from '@veramo/utils'

type BlsBackend = 'chainsafe' | 'noble'

function resolveBlsBackend(value: unknown): BlsBackend {
  return value === 'noble' ? 'noble' : 'chainsafe'
}

function strip0x(hex: string): string {
  return hex.startsWith('0x') ? hex.slice(2) : hex
}

let chainsafeBlsPromise: Promise<any> | undefined
async function getChainsafeBls(): Promise<any> {
  if (!chainsafeBlsPromise) {
    chainsafeBlsPromise = import('@chainsafe/bls').then((m: any) => m?.default ?? m)
  }
  return chainsafeBlsPromise
}

let nobleBlsPromise: Promise<any> | undefined
async function getNobleBls(): Promise<any> {
  if (!nobleBlsPromise) {
    nobleBlsPromise = import('@noble/curves/bls12-381').then((m: any) => m.bls12_381)
  }
  return nobleBlsPromise
}

async function getBlsKeyHex(kid: string): Promise<string> {
  const key = await agent.keyManagerGet({ kid })
  return key.publicKeyHex
}

/**
 * Create a Proof of Possession for a single Actor (by BLS key kid).
 *
 * - Binds the proof to the exact BLS public key and a caller-provided nonce.
 * - Uses a canonical JSON message for deterministic signing.
 * - Returns the message (what was signed), the signature, and the publicKeyHex.
 */
export async function createProofOfPossessionPerActor(
  kid_bls: string,
  nonce: string,
): Promise<{ message: string; signature: string; publicKeyHex: string }> {
  if (!kid_bls) throw new Error('kid_bls is required')
  if (!nonce) throw new Error('nonce is required')

  const publicKeyHex = await getBlsKeyHex(kid_bls)

  const messageObj = {
    type: 'BLS-ProofOfPossession',
    alg: 'BLS_SIGNATURE',
    publicKeyHex,
    nonce,
  }
  const message = JSON.stringify(messageObj)

  const signature = await agent.keyManagerSign({
    keyRef: kid_bls,
    data: message,
    algorithm: 'BLS_SIGNATURE',
    encoding: 'utf-8',
  })

  return { message, signature, publicKeyHex }
}

/**
 * Verify a Proof of Possession (PoP) produced by createProofOfPossessionPerActor.
 */
export async function verifyProofOfPossessionStrict(
  message: string,
  signatureHex: string,
  expectedNonce: string,
  expectedPublicKeyHex: string,
): Promise<{ valid: boolean; reason?: string; publicKeyHex: string; nonce: string }> {
  if (!message) return { valid: false, reason: 'Missing message', publicKeyHex: '', nonce: '' }
  if (!signatureHex) return { valid: false, reason: 'Missing signatureHex', publicKeyHex: '', nonce: '' }
  if (!expectedNonce) return { valid: false, reason: 'Missing expectedNonce', publicKeyHex: '', nonce: '' }
  if (!expectedPublicKeyHex) return { valid: false, reason: 'Missing expectedPublicKeyHex', publicKeyHex: '', nonce: '' }

  let parsed: any
  try {
    parsed = JSON.parse(message)
  } catch {
    return { valid: false, reason: 'Message is not valid JSON', publicKeyHex: '', nonce: '' }
  }

  if (parsed?.type !== 'BLS-ProofOfPossession' || parsed?.alg !== 'BLS_SIGNATURE') {
    return { valid: false, reason: 'Invalid PoP domain fields', publicKeyHex: '', nonce: '' }
  }

  const publicKeyHexInMsg: string | undefined = parsed?.publicKeyHex
  const nonceInMsg: string | undefined = parsed?.nonce
  if (!publicKeyHexInMsg) return { valid: false, reason: 'Missing publicKeyHex in message', publicKeyHex: '', nonce: nonceInMsg || '' }
  if (!nonceInMsg) return { valid: false, reason: 'Missing nonce in message', publicKeyHex: publicKeyHexInMsg, nonce: '' }

  if (publicKeyHexInMsg !== expectedPublicKeyHex) {
    return { valid: false, reason: 'Public key mismatch', publicKeyHex: publicKeyHexInMsg, nonce: nonceInMsg }
  }
  if (nonceInMsg !== expectedNonce) {
    return { valid: false, reason: 'Nonce mismatch', publicKeyHex: publicKeyHexInMsg, nonce: nonceInMsg }
  }

  const backend = resolveBlsBackend(process.env.VERAMO_BLS_BACKEND)
  const pkHex = strip0x(publicKeyHexInMsg)
  const sigHex = strip0x(signatureHex)

  try {
    const msgBytes = new TextEncoder().encode(message)
    if (backend === 'noble') {
      const bls = await getNobleBls()
      const ok = bls.verify(hexToBytes(sigHex), msgBytes, hexToBytes(pkHex))
      return ok
        ? { valid: true, publicKeyHex: publicKeyHexInMsg, nonce: nonceInMsg }
        : { valid: false, reason: 'BLS verification failed', publicKeyHex: publicKeyHexInMsg, nonce: nonceInMsg }
    } else {
      const bls = await getChainsafeBls()
      const pk = bls.PublicKey.fromHex(pkHex)
      const sig = bls.Signature.fromHex(sigHex)
      const ok = bls.verify(pk, msgBytes, sig)
      return ok
        ? { valid: true, publicKeyHex: publicKeyHexInMsg, nonce: nonceInMsg }
        : { valid: false, reason: 'BLS verification failed', publicKeyHex: publicKeyHexInMsg, nonce: nonceInMsg }
    }
  } catch (e: any) {
    return { valid: false, reason: `Verification error: ${e?.message || e}`, publicKeyHex: publicKeyHexInMsg, nonce: nonceInMsg }
  }
}

