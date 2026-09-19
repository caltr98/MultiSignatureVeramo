import type {
  IKey,
  ManagedKeyInfo,
  MinimalImportableKey,
  TKeyType,
} from '@veramo/core-types'
import type {
  AbstractPrivateKeyStore,
  ManagedPrivateKey,
} from '@veramo/key-manager'
import { KeyManagementSystem } from '@veramo/kms-local'
import { BlsCrypto, type BlsBackend } from './bls.js'

type SignArgs = {
  keyRef: Pick<IKey, 'kid'>
  algorithm?: string
  data: Uint8Array
}

// The standard KMS owns its supported key types; BLS entries use the same backing store.
function standardKeys(store: AbstractPrivateKeyStore): AbstractPrivateKeyStore {
  return {
    importKey: store.importKey.bind(store),
    getKey: store.getKey.bind(store),
    deleteKey: store.deleteKey.bind(store),
    listKeys: async (args) =>
      (await store.listKeys(args)).filter((key) => key.type !== 'Bls12381G1'),
  }
}

function readSignatures(data: Uint8Array): string[] {
  const parsed = JSON.parse(new TextDecoder().decode(data)) as {
    signatures?: unknown
  } | null
  const signatures = parsed?.signatures
  if (
    !Array.isArray(signatures) ||
    signatures.length === 0 ||
    signatures.some((value) => typeof value !== 'string')
  ) {
    throw new Error(
      'invalid_argument: signatures must be a non-empty array of hex strings',
    )
  }
  return signatures
}

/** Adds BLS keys and aggregation to Veramo's maintained local KMS. */
export class BlsKeyManagementSystem extends KeyManagementSystem {
  private readonly bls: BlsCrypto

  constructor(
    private readonly privateKeyStore: AbstractPrivateKeyStore,
    options?: { blsBackend?: BlsBackend },
  ) {
    super(standardKeys(privateKeyStore))
    this.bls = new BlsCrypto(options?.blsBackend)
  }

  async importKey(
    args: Omit<MinimalImportableKey, 'kms'>,
  ): Promise<ManagedKeyInfo> {
    if (args.type !== 'Bls12381G1') return super.importKey(args)
    const key = await this.describeBlsKey({ ...args, alias: args.kid })
    await this.privateKeyStore.importKey({ ...args, alias: key.kid })
    return key
  }

  async createKey(args: { type: TKeyType }): Promise<ManagedKeyInfo> {
    if (args.type !== 'Bls12381G1') return super.createKey(args)
    return this.importKey({
      type: args.type,
      privateKeyHex: await this.bls.createPrivateKey(),
    })
  }

  async listKeys(): Promise<ManagedKeyInfo[]> {
    const keys = (await this.privateKeyStore.listKeys({})).filter(
      (key) => key.type === 'Bls12381G1',
    )
    return [
      ...(await super.listKeys()),
      ...(await Promise.all(keys.map((key) => this.describeBlsKey(key)))),
    ]
  }

  async sign(args: SignArgs): Promise<string> {
    const key = await this.privateKeyStore.getKey({ alias: args.keyRef.kid })
    if (key.type !== 'Bls12381G1') return super.sign(args)
    return this.signBls(key, args)
  }

  private async signBls(
    key: ManagedPrivateKey,
    { algorithm, data }: SignArgs,
  ): Promise<string> {
    if (algorithm === 'BLS_SIGNATURE')
      return this.bls.sign(key.privateKeyHex, data)
    if (algorithm === 'BLS_AGGREGATE_MULTI_SIGNATURE')
      return this.bls.aggregateSignatures(readSignatures(data))
    throw new Error(`not_supported: Cannot sign ${algorithm} using a BLS key`)
  }

  private async describeBlsKey(
    key: Pick<ManagedPrivateKey, 'privateKeyHex'> & { alias?: string },
  ): Promise<ManagedKeyInfo> {
    const publicKeyHex = await this.bls.publicKey(key.privateKeyHex)
    // KeyManager supplies the registered KMS name, as it does for the standard local KMS.
    return {
      type: 'Bls12381G1',
      kid: key.alias ?? publicKeyHex,
      publicKeyHex,
      meta: { algorithms: ['BLS_SIGNATURE', 'BLS_AGGREGATE_MULTI_SIGNATURE'] },
    } as ManagedKeyInfo
  }
}
