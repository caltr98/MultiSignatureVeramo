// Setup agents for the no-multisig EIP712 baseline (one issuer = one VC)
import { agent } from '../veramo/setup_eip712.js';
import { Wallet } from 'ethers';
let agents = [];
let seq_agent = 0;
function uniqueAlias(prefix) {
    return `${prefix}-${process.pid}-${Date.now()}-${seq_agent++}`;
}
async function createAgent(name) {
    const wallet = Wallet.createRandom();
    const ethPrivateKey = wallet.privateKey.replace(/^0x/, '');
    const ethAddress = await wallet.getAddress();
    const key = {
        type: 'Secp256k1',
        privateKeyHex: ethPrivateKey,
        kms: 'local',
    };
    const kid = await agent.keyManagerImport(key);
    const did = `did:ethr:sepolia:${ethAddress}`;
    const identifier = await agent.didManagerImport({
        did,
        provider: 'did:ethr:sepolia',
        alias: uniqueAlias(name),
        controllerKeyId: kid.kid,
        keys: [key],
    });
    return { did: identifier.did, keyRef: kid.kid };
}
export async function setup_agents(numberOfAgents = 3) {
    const agentList = [];
    for (let i = 0; i < numberOfAgents; i++) {
        const agentInfo = await createAgent('agent');
        agentList.push(agentInfo);
    }
    agents.push(...agentList);
    return agentList;
}
export async function cleanup() {
    const allDids = await agent.didManagerFind();
    for (const d of allDids) {
        await agent.didManagerDelete({ did: d.did });
    }
}
