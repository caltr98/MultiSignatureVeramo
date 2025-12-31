import { agent } from '../veramo/setup.js';
import { Wallet } from 'ethers';
/**
 * Create a single actor identity with:
 * - an EthrDID + Ethereum signing key (for PoO)
 * - a BLS key (not published to DID doc)
 */
export async function singleActorSetup(name = 'actor1') {
    const wallet = Wallet.createRandom();
    const ethPrivateKey = wallet.privateKey.replace(/^0x/, '');
    const ethAddress = await wallet.getAddress();
    const ethKey = {
        type: 'Secp256k1',
        privateKeyHex: ethPrivateKey,
        kms: 'local',
    };
    const eth_kid = await agent.keyManagerImport(ethKey);
    const did = `did:ethr:sepolia:${ethAddress}`;
    const identifier = await agent.didManagerImport({
        did,
        provider: 'did:ethr:sepolia',
        alias: name,
        controllerKeyId: eth_kid.kid,
        keys: [ethKey],
    });
    const blsKey = await agent.keyManagerCreate({
        kms: 'local',
        type: 'Bls12381G1',
    });
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
