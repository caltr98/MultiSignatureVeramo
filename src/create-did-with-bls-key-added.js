import { agent } from './veramo/setup.js';
async function main() {
    let identifier;
    // 1. Dati noti
    const privKeyHex = '5e9c48b3b8f10589adac746ea63b63dfcbd4708ff032fd0dcc9c7c1aa045a53c';
    const address = "0x03A7C4B3126E57bABe1206090C52F4070A9b381e";
    //const privKeyHex = '423c950596abae910e6bc845859ba561b1977cffae4174f2c9c40596c2903261'
    //const address = "0xc97F8bEb6A5abE8a1dA85AF4649f2eB356194fed"
    // 2. Registra la chiave e il DID
    identifier = await agent.didManagerImport({
        did: `did:ethr:sepolia:${address}`,
        provider: 'did:ethr:sepolia',
        controllerKeyId: `key-${address}`,
        keys: [
            {
                kid: `key-${address}`,
                type: 'Secp256k1',
                kms: 'local',
                privateKeyHex: privKeyHex,
                meta: {
                    algorithms: ['eth_signTransaction', 'eth_signTypedData', 'eth_rawSign']
                }
            }
        ],
        services: [],
    });
    console.log('✅ Imported DID:', identifier.did);
    console.log(JSON.stringify(identifier, null, 2));
    //const dummyKey = await agent.keyManagerCreate({kms: 'local', type: 'Bls12381G1'})
    const dummyKey = await agent.keyManagerCreate({ kms: 'local', type: 'Bls12381G1' });
    const addedKeyResult = await agent.didManagerAddKey({ did: identifier.did, key: dummyKey });
    console.log(JSON.stringify(addedKeyResult, null, 2));
}
main().catch(console.log);
