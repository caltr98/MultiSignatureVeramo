// Agent setup that includes the EIP712 credential plugin (baseline / no-multisig).
import { createAgent, } from '@veramo/core';
import { getResolver } from 'ethr-did-resolver';
import { KeyManager } from '@veramo/key-manager';
import { CredentialIssuerEIP712 } from '@veramo/credential-eip712';
import { CredentialPlugin } from '@veramo/credential-w3c';
import { DIDResolverPlugin } from '@veramo/did-resolver';
import { Resolver } from 'did-resolver';
import { Entities, KeyStore, DIDStore, PrivateKeyStore, migrations, DataStore, } from '@veramo/data-store';
import { DataSource } from 'typeorm';
import { KeyManagementSystem, SecretBox } from '@veramo/kms-local';
import { DIDManager } from '@veramo/did-manager';
import { EthrDIDProvider } from '@veramo/did-provider-ethr';
//Alchemy is 100% better than Infura for Ethr DID provider
const ethrResolverAlchemy = getResolver({
    networks: [
        {
            name: 'sepolia',
            rpcUrl: 'https://eth-sepolia.g.alchemy.com/v2/WrB3Vk1T7hkQzsi6u_oeRMNeoRrvFX80',
            registry: '0x03d5003bf0e79C5F5223588F347ebA39AfbC3818',
        },
    ],
});
// Keep the EIP712/no-multisig baseline isolated from the multisig/BLS experiments.
// This avoids cross-test state (eg. unique alias constraints) when re-running scripts.
const DATABASE_FILE = process.env.VERAMO_DB_EIP712 || 'database_eip712.sqlite';
const KMS_SECRET_KEY = 'f1baa0637294cbe40f68c8f2c16cc2a96982db8dde5a5a4b4f485f0ca2272069';
// Remote-only DID resolution (required by EIP712 verification).
const resolver = new Resolver(ethrResolverAlchemy);
const dbConnection = new DataSource({
    type: 'sqlite',
    database: DATABASE_FILE,
    synchronize: false,
    migrations,
    migrationsRun: true,
    logging: ['error', 'info', 'warn'],
    entities: Entities,
}).initialize();
export const agent = createAgent({
    plugins: [
        new KeyManager({
            store: new KeyStore(dbConnection),
            kms: {
                local: new KeyManagementSystem(new PrivateKeyStore(dbConnection, new SecretBox(KMS_SECRET_KEY))),
            },
        }),
        new DIDManager({
            store: new DIDStore(dbConnection),
            defaultProvider: 'did:ethr:sepolia',
            providers: {
                'did:ethr:sepolia': new EthrDIDProvider({
                    defaultKms: 'local',
                    network: 'sepolia',
                    rpcUrl: 'https://eth-sepolia.g.alchemy.com/v2/WrB3Vk1T7hkQzsi6u_oeRMNeoRrvFX80',
                }),
            },
        }),
        new DIDResolverPlugin({
            resolver,
        }),
        new CredentialIssuerEIP712(),
        // Provides `createVerifiablePresentation`/`verifyPresentation` for the baseline VP flow (jwt/lds),
        // while VCs are issued via EIP712 using CredentialIssuerEIP712.
        new CredentialPlugin(),
        new DataStore(dbConnection),
    ],
});
