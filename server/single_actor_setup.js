import { agent } from '../src/veramo/setup.js';
import { Wallet } from "ethers";
/**
 * Create a single actor identity with:
 * - an EthrDID + Ethereum signing key (for PoO)
 * - a BLS key (not published to DID doc)
 */
export async function singleActorSetup(name = 'actor1') {
    // 1. Generate Ethereum keypair
    const wallet = Wallet.createRandom();
    const ethPrivateKey = wallet.privateKey.replace(/^0x/, '');
    const ethAddress = await wallet.getAddress();
    const ethKey = {
        type: 'Secp256k1',
        privateKeyHex: ethPrivateKey,
        kms: 'local',
    };
    // Import Ethereum key into agent
    const eth_kid = await agent.keyManagerImport(ethKey);
    // Build DID (network: sepolia in your example)
    const did = `did:ethr:sepolia:${ethAddress}`;
    // Register DID with Veramo
    const identifier = await agent.didManagerImport({
        did,
        provider: 'did:ethr:sepolia',
        alias: name,
        controllerKeyId: eth_kid.kid,
        keys: [ethKey],
    });
    // 2. Generate BLS keypair
    const blsKey = await agent.keyManagerCreate({
        kms: 'local',
        type: 'Bls12381G1',
    });
    // Attach BLS key to DID (without publishing in DID doc)
    await agent.didManagerAddKey({
        did: identifier.did,
        key: blsKey,
        key_type: 'Bls12381G1',
        key_ref: blsKey.kid,
        NoPublish: true,
    });
    return {
        did: identifier.did,
        kid_bls: blsKey.kid,
        bls_pub_key: blsKey.publicKeyHex,
        kid_eth: eth_kid.kid,
    };
}
