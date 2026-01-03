// Setup agents for the no-multisig EIP712 baseline (one issuer = one VC)
import { agent } from '../veramo/setup_eip712.js'
import { Wallet } from 'ethers'
import { MinimalImportableKey } from '@veramo/core-types'

interface AgentInfo {
  did: string
  keyRef: string
}

let agents: AgentInfo[] = []
let seq_agent = 0

function uniqueAlias(prefix: string): string {
  return `${prefix}-${process.pid}-${Date.now()}-${seq_agent++}`
}

async function createAgent(name: string): Promise<AgentInfo> {
  const wallet = Wallet.createRandom()
  const ethPrivateKey = wallet.privateKey.replace(/^0x/, '')
  const ethAddress = await wallet.getAddress()

  const key = {
    type: 'Secp256k1',
    privateKeyHex: ethPrivateKey,
    kms: 'local',
  } as MinimalImportableKey

  const kid = await agent.keyManagerImport(key)

  const did = `did:ethr:sepolia:${ethAddress}`
  const identifier = await agent.didManagerImport({
    did,
    provider: 'did:ethr:sepolia',
    alias: uniqueAlias(name),
    controllerKeyId: kid.kid,
    keys: [key],
  })

  return { did: identifier.did, keyRef: kid.kid }
}

export async function setup_agents(numberOfAgents: number = 3): Promise<AgentInfo[]> {
  const agentList: AgentInfo[] = []
  for (let i = 0; i < numberOfAgents; i++) {
    const agentInfo = await createAgent('agent')
    agentList.push(agentInfo)
  }
  agents.push(...agentList)
  return agentList
}

export async function cleanup() {
  const allDids = await agent.didManagerFind()
  for (const d of allDids) {
    await agent.didManagerDelete({ did: d.did })
  }
}
