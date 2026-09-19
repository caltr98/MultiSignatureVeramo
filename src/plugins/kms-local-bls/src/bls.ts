import { bytesToHex, hexToBytes } from '@veramo/utils'

export type BlsBackend = 'chainsafe' | 'noble'
type ChainSafe = (typeof import('@chainsafe/bls'))['default']
type Noble = (typeof import('@noble/curves/bls12-381'))['bls12_381']

let chainsafe: Promise<ChainSafe> | undefined
let noble: Promise<Noble> | undefined

function loadChainSafe(): Promise<ChainSafe> {
  return (chainsafe ??= import('@chainsafe/bls').then(
    (module) => module.default,
  ))
}

function loadNoble(): Promise<Noble> {
  return (noble ??= import('@noble/curves/bls12-381').then(
    (module) => module.bls12_381,
  ))
}

export function resolveBlsBackend(
  value = typeof process === 'undefined'
    ? undefined
    : process.env.VERAMO_BLS_BACKEND,
): BlsBackend {
  if (value === undefined || value === 'chainsafe') return 'chainsafe'
  if (value === 'noble') return 'noble'
  throw new Error(`Unsupported BLS backend: ${value}`)
}

export function blsBytes(hex: string): Uint8Array {
  const value = typeof hex === 'string' ? hex.replace(/^0x/i, '') : ''
  if (!value || value.length % 2 || !/^[0-9a-f]+$/i.test(value))
    throw new Error('Expected non-empty hexadecimal BLS material')
  return hexToBytes(value)
}

function readPoints(points: string[]): Uint8Array[] {
  if (!Array.isArray(points) || points.length === 0)
    throw new Error('BLS aggregation requires a non-empty array')
  return points.map(blsBytes)
}

/** Byte-oriented BLS operations shared by key management and credential verification. */
export class BlsCrypto {
  readonly backend: BlsBackend

  constructor(backend?: BlsBackend) {
    this.backend = resolveBlsBackend(backend)
  }

  async createPrivateKey(): Promise<string> {
    const bytes =
      this.backend === 'noble'
        ? (await loadNoble()).utils.randomPrivateKey()
        : (await loadChainSafe()).SecretKey.fromKeygen().toBytes()
    return bytesToHex(bytes)
  }

  async publicKey(privateKeyHex: string): Promise<string> {
    const key = blsBytes(privateKeyHex)
    const bytes =
      this.backend === 'noble'
        ? (await loadNoble()).getPublicKey(key)
        : (await loadChainSafe()).secretKeyToPublicKey(key)
    return bytesToHex(bytes)
  }

  async sign(privateKeyHex: string, message: Uint8Array): Promise<string> {
    const key = blsBytes(privateKeyHex)
    const bytes =
      this.backend === 'noble'
        ? (await loadNoble()).sign(message, key)
        : (await loadChainSafe()).sign(key, message)
    return bytesToHex(bytes)
  }

  async aggregateSignatures(signatures: string[]): Promise<string> {
    const points = readPoints(signatures)
    const backend =
      this.backend === 'noble' ? await loadNoble() : await loadChainSafe()
    return bytesToHex(backend.aggregateSignatures(points))
  }

  async aggregatePublicKeys(publicKeys: string[]): Promise<string> {
    const points = readPoints(publicKeys)
    const backend =
      this.backend === 'noble' ? await loadNoble() : await loadChainSafe()
    return bytesToHex(backend.aggregatePublicKeys(points))
  }

  async verify(
    publicKey: string,
    message: Uint8Array,
    signature: string,
  ): Promise<boolean> {
    const [key, proof] = [blsBytes(publicKey), blsBytes(signature)]
    return this.backend === 'noble'
      ? (await loadNoble()).verify(proof, message, key)
      : (await loadChainSafe()).verify(key, message, proof)
  }
}
