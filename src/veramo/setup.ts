// Core interfaces
import {
    createAgent,
    IResolver,
    IDataStore,
    IKeyManager,
    ICredentialPlugin,
    IMessageHandler
} from '@veramo/core'
import { getResolver } from "ethr-did-resolver";

// Core identity manager plugin
import { DIDManager } from '@veramo/did-manager'

// Ethr did identity provider
import { EthrDIDProvider } from '@veramo/did-provider-ethr'

//Alchemy is 100% better than Infura for Ethr DID provider
const ethrResolverAlchemy = getResolver({
    networks: [
        {
            name: 'sepolia',
            rpcUrl: 'http://127.0.0.1:8545',
            registry: '0x03d5003bf0e79C5F5223588F347ebA39AfbC3818',
        },
    ],
})

// Core key manager plugin
import { KeyManager } from '@veramo/key-manager'

import {BlsKeyManagementSystem} from "./../plugins/kms-local-bls/src/key-management-system-bls.js";

import {BlsEthrDIDProvider} from '../plugins/did-provider-BLS-Ethr/src/bls-ethr-did-provider.js';

// Custom key management system for RN
import { KeyManagementSystem, SecretBox } from '@veramo/kms-local'

// W3C Verifiable Credential plugin
import {CredentialPlugin, ICustomCredentialPlugin} from '../plugins/bls-extend-credential-w3c/src/action-handler.js'

// Custom resolvers
import { DIDResolverPlugin } from '@veramo/did-resolver'
import { Resolver } from 'did-resolver'
import { getResolver as ethrDidResolver } from 'ethr-did-resolver'


// Storage plugin using TypeOrm
import {
    Entities,
    KeyStore,
    DIDStore,
    IDataStoreORM,
    PrivateKeyStore,
    migrations,
    DataStore,
} from '@veramo/data-store'
import { MessageHandler } from '@veramo/message-handler'

// TypeORM is installed with `@veramo/data-store`
import { DataSource } from 'typeorm'
import {DIDManagerBls} from "../plugins/did-manager-bls/src/bls-id-manager.js";
import {IDIDManager} from "@veramo/core-types";

// This will be the name for the local sqlite database for demo purposes
const DATABASE_FILE = 'database.sqlite'

// You will need to get a project ID from infura https://www.infura.io
const INFURA_PROJECT_ID = '77b6397329f849c0b5746b7da777c7dd'

// This will be the secret key for the KMS
const KMS_SECRET_KEY =
  'f1baa0637294cbe40f68c8f2c16cc2a96982db8dde5a5a4b4f485f0ca2272069'

  const dbConnection = new DataSource({
    type: 'sqlite',
    database: DATABASE_FILE,
    synchronize: false,
    migrations,
    migrationsRun: true,
    logging: ['error', 'info', 'warn'],
    entities: Entities,
  }).initialize()

//NOTE: PUTTING REGISTRY IS FUNDEMENTAL, OR ELSE NO TRANSACTIONS WILL PASS
export const agent = createAgent<
    IMessageHandler &IDIDManager & IKeyManager & IDataStore & IDataStoreORM & IResolver & ICustomCredentialPlugin & ICredentialPlugin
>({
    plugins: [
        new KeyManager({
            store: new KeyStore(dbConnection),
            kms: {
                local: new BlsKeyManagementSystem(
                    new PrivateKeyStore(dbConnection, new SecretBox(KMS_SECRET_KEY))
                ),
            },
        }),
        new DIDManagerBls({
            store: new DIDStore(dbConnection),
            defaultProvider: 'did:ethr:sepolia',
            providers: {
                'did:ethr:sepolia': new BlsEthrDIDProvider({
                    defaultKms: 'local',
                    network: 'sepolia',
                    registry:"0x03d5003bf0e79C5F5223588F347ebA39AfbC3818",
                    rpcUrl: "https://eth-sepolia.g.alchemy.com/v2/WrB3Vk1T7hkQzsi6u_oeRMNeoRrvFX80"
                }),
            },
        }),
        new DIDResolverPlugin({
            resolver: new Resolver(ethrResolverAlchemy),
        }),
        new CredentialPlugin(),
        new DataStore(dbConnection),             // <--- Required to store VC
    ],
})
