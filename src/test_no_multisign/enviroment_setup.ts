// This file sets up a set of Veramo Agents
// Each has their own DID and Keypair for EthrDID, plus a BLS keypair for BLS Signature

import { agent } from '../veramo/setup.js'
import {IDIDBlsManagerAddKeyArgs} from "../plugins/did-manager-bls/src/bls-id-manager.js";
import {Wallet} from "ethers";
import {MinimalImportableKey} from "@veramo/core-types";

interface AgentInfo {
    did: string
}

let agents: AgentInfo[] = []

let seq_agent = 0;
/**
 * Creates a new Veramo agent identity with a BLS key
 */
async function createAgent(name: string): Promise<{ did: string }> {

    // 1. Generate Ethereum key first
    const wallet = Wallet.createRandom();
    const ethPrivateKey = wallet.privateKey.replace(/^0x/, '');
    const ethAddress = await wallet.getAddress();


    const key = {
        type: 'Secp256k1',
        privateKeyHex: ethPrivateKey,
        kms: 'local',
    } as MinimalImportableKey;

    const kid = await agent.keyManagerImport(key);

    const did = `did:ethr:sepolia:${ethAddress}`; // or goerli, mainnet, etc

    const identifier = await agent.didManagerImport({
        did,
        provider: 'did:ethr:sepolia',
        alias: name,
        controllerKeyId: kid.kid,
        keys: [key],
    });


    return { did: identifier.did }
}

/**
 * Sets up a given number of agents
 */
export async function setup_agents(numberOfAgents: number = 3): Promise<AgentInfo[]> {
    const agentList: AgentInfo[] = []
    for (let i = 0; i < numberOfAgents; i++) {
        const agentInfo = await createAgent(`agent${seq_agent++}`)
        agentList.push(agentInfo)
    }
    agents.push(...agentList)  // store in global list for cleanup
    return agentList
}

/**
 * Cleans up all created agents and their keys including BLS ones
 */
export async function cleanup() {
    const allDids = await agent.didManagerFind()
    for (const d of allDids) {
        await agent.didManagerDelete({did: d.did})
    }

}