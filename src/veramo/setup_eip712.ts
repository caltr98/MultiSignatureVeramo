import { createAgent } from '@veramo/core'
import type {
  ICredentialPlugin,
  IDataStore,
  IDIDManager,
  IKeyManager,
  IResolver,
} from '@veramo/core-types'
import { KeyManager } from '@veramo/key-manager'
import { SecretBox, KeyManagementSystem } from '@veramo/kms-local'
import {
  DataStore,
  DIDStore,
  KeyStore,
  PrivateKeyStore,
} from '@veramo/data-store'
import { DIDResolverPlugin } from '@veramo/did-resolver'
import { Resolver } from 'did-resolver'
import { getResolver } from 'ethr-did-resolver'
import { demoConfig, demoDatabase } from './demo-config.js'
import { DIDManager } from '@veramo/did-manager'
import { EthrDIDProvider } from '@veramo/did-provider-ethr'
import { CredentialPlugin } from '@veramo/credential-w3c'
import { CredentialProviderJWT } from '@veramo/credential-jwt'
import { CredentialProviderEIP712 } from '@veramo/credential-eip712'

const config = demoConfig('VERAMO_DB_EIP712')
const database = demoDatabase(config.database)
const network = {
  name: 'sepolia',
  rpcUrl: config.rpcUrl,
  registry: config.registry,
}

export const agent = createAgent<
  IDIDManager & IKeyManager & IDataStore & IResolver & ICredentialPlugin
>({
  plugins: [
    new KeyManager({
      store: new KeyStore(database),
      kms: {
        local: new KeyManagementSystem(
          new PrivateKeyStore(database, new SecretBox(config.secretKey)),
        ),
      },
    }),
    new DIDManager({
      store: new DIDStore(database),
      defaultProvider: 'did:ethr:sepolia',
      providers: {
        'did:ethr:sepolia': new EthrDIDProvider({
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
    new CredentialPlugin([
      new CredentialProviderJWT(),
      new CredentialProviderEIP712(),
    ]),
    new DataStore(database),
  ],
})
