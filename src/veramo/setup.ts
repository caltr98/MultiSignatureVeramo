import { createAgent } from '@veramo/core'
import type {
  ICredentialPlugin,
  IDataStore,
  IDIDManager,
  IKeyManager,
  IResolver,
} from '@veramo/core-types'
import { KeyManager } from '@veramo/key-manager'
import { SecretBox } from '@veramo/kms-local'
import {
  DataStore,
  DataStoreORM,
  DIDStore,
  KeyStore,
  PrivateKeyStore,
  type IDataStoreORM,
} from '@veramo/data-store'
import { DIDResolverPlugin } from '@veramo/did-resolver'
import { Resolver } from 'did-resolver'
import { getResolver } from 'ethr-did-resolver'
import { demoConfig, demoDatabase } from './demo-config.js'
import {
  BlsKeyManagementSystem,
  resolveBlsBackend,
} from '@veramo-community/kms-local-bls'
import { DIDManagerBls } from '@veramo-community/did-manager-bls'
import { BlsEthrDIDProvider } from '@veramo-community/did-provider-ethr-bls'
import {
  CredentialPlugin,
  type ICustomCredentialPlugin,
} from '@veramo-community/credential-w3c-bls-multisig'

const config = demoConfig()
const database = demoDatabase(config.database)
const network = {
  name: 'sepolia',
  rpcUrl: config.rpcUrl,
  registry: config.registry,
}
const blsBackend = resolveBlsBackend()
export const agent = createAgent<
  IDIDManager &
    IKeyManager &
    IDataStore &
    IDataStoreORM &
    IResolver &
    ICredentialPlugin &
    ICustomCredentialPlugin
>({
  plugins: [
    new KeyManager({
      store: new KeyStore(database),
      kms: {
        local: new BlsKeyManagementSystem(
          new PrivateKeyStore(database, new SecretBox(config.secretKey)),
          { blsBackend },
        ),
      },
    }),
    new DIDManagerBls({
      store: new DIDStore(database),
      defaultProvider: 'did:ethr:sepolia',
      providers: {
        'did:ethr:sepolia': new BlsEthrDIDProvider({
          defaultKms: 'local',
          network: 'sepolia',
          rpcUrl: config.rpcUrl,
          registry: config.registry,
        }),
      },
    }),
    new DIDResolverPlugin({
      resolver: new Resolver(getResolver({ networks: [network] })),
    }),
    new CredentialPlugin({ blsBackend }),
    new DataStore(database),
    new DataStoreORM(database),
  ],
})
