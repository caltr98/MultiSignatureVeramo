// Core interfaces
import { createAgent } from '@veramo/core';
// Core identity manager plugin
import { DIDManager } from '@veramo/did-manager';
// Core key manager plugin
import { KeyManager } from '@veramo/key-manager';
import { BlsKeyManagementSystem } from "./../plugins/kms-local-bls/src/key-management-system-bls.js";
import { BlsEthrDIDProvider } from '../plugins/did-provider-BLS-Ethr/src/bls-ethr-did-provider.js';
// Custom key management system for RN
import { SecretBox } from '@veramo/kms-local';
// W3C Verifiable Credential plugin
import { CredentialPlugin } from '../plugins/bls-extend-credential-w3c/src/action-handler.js';
// Custom resolvers
import { DIDResolverPlugin } from '@veramo/did-resolver';
import { Resolver } from 'did-resolver';
import { getResolver as ethrDidResolver } from 'ethr-did-resolver';
import { getResolver as webDidResolver } from 'web-did-resolver';
// Storage plugin using TypeOrm
import { Entities, KeyStore, DIDStore, PrivateKeyStore, migrations } from '@veramo/data-store';
// TypeORM is installed with `@veramo/data-store`
import { DataSource } from 'typeorm';
// This will be the name for the local sqlite database for demo purposes
const DATABASE_FILE = 'database.sqlite';
// You will need to get a project ID from infura https://www.infura.io
const INFURA_PROJECT_ID = '77b6397329f849c0b5746b7da777c7dd';
// This will be the secret key for the KMS
const KMS_SECRET_KEY = 'f1baa0637294cbe40f68c8f2c16cc2a96982db8dde5a5a4b4f485f0ca2272069';
const dbConnection = new DataSource({
    type: 'sqlite',
    database: DATABASE_FILE,
    synchronize: false,
    migrations,
    migrationsRun: true,
    logging: ['error', 'info', 'warn'],
    entities: Entities,
}).initialize();
//NOTE: PUTTING REGISTRY IS FUNDEMENTAL, OR ELSE NO TRANSACTIONS WILL PASS
export const agent = createAgent({
    plugins: [
        new KeyManager({
            store: new KeyStore(dbConnection),
            kms: {
                local: new BlsKeyManagementSystem(new PrivateKeyStore(dbConnection, new SecretBox(KMS_SECRET_KEY))),
            },
        }),
        new DIDManager({
            store: new DIDStore(dbConnection),
            defaultProvider: 'did:ethr:sepolia',
            providers: {
                'did:ethr:sepolia': new BlsEthrDIDProvider({
                    defaultKms: 'local',
                    network: 'sepolia',
                    registry: "0x03d5003bf0e79C5F5223588F347ebA39AfbC3818",
                    rpcUrl: 'https://sepolia.infura.io/v3/' + INFURA_PROJECT_ID,
                }),
            },
        }),
        new DIDResolverPlugin({
            resolver: new Resolver({
                ...ethrDidResolver({ infuraProjectId: INFURA_PROJECT_ID }),
                ...webDidResolver(),
            }),
        }),
        new CredentialPlugin(),
    ],
});
