// This file sets up a set of Veramo Agents
// Each has their own DID and Keypair for EthrDID, plus a BLS keypair for BLS Signature
import { agent } from '../src/veramo/setup.js';
import { Wallet } from "ethers";
let agents = [];
let seq_agent = 0;
/**
 * Creates a new Veramo agent identity with a BLS key
 */
async function createAgent(name) {
    // 1. Generate Ethereum key first
    const wallet = Wallet.createRandom();
    const ethPrivateKey = wallet.privateKey.replace(/^0x/, '');
    const ethAddress = await wallet.getAddress();
    const key = {
        type: 'Secp256k1',
        privateKeyHex: ethPrivateKey,
        kms: 'local',
    };
    const kid = await agent.keyManagerImport(key);
    const did = `did:ethr:sepolia:${ethAddress}`; // or goerli, mainnet, etc
    const identifier = await agent.didManagerImport({
        did,
        provider: 'did:ethr:sepolia',
        alias: name,
        controllerKeyId: kid.kid,
        keys: [key],
    });
    const dummyKey = await agent.keyManagerCreate({
        kms: 'local',
        type: 'Bls12381G1',
    });
    //fundemental to create a custom agent that does not publish the bls key on the did doc by default!
    const res = await agent.didManagerAddKey({
        did: identifier.did,
        key: dummyKey,
        key_type: 'Bls12381G1',
        key_ref: dummyKey.kid,
        NoPublish: true // custom flag to skip provider.addKey() and avoid having bls pub key on did doc
    });
    //console.log(dummyKey)
    return { did: identifier.did, kid_bls: dummyKey.kid, bls_pub_key: dummyKey.publicKeyHex };
}
/**
 * Cleans up all created agents and their keys including BLS ones
 */
export async function cleanup() {
    const allDids = await agent.didManagerFind();
    for (const d of allDids) {
        await agent.didManagerDelete({ did: d.did });
    }
}
