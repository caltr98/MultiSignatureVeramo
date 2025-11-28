// AI agents layer orchestrating collaborative credential issuance.

import { ChatOpenAI } from '@langchain/openai'
import { ChatPromptTemplate } from '@langchain/core/prompts'
import type { IAgent } from '@veramo/core-types'
import type { ICreateVerifiableCredentialArgs, VerifiableCredential } from '@veramo/credential-w3c'
import { agent as veramoAgent } from './veramo/setup.js'
import {
  aggregatePartialSignatures,
  finalizeMultiIssuedCredential,
  signMultiIssuedVerifiableCredential,
} from './simulation.js'

// Shared context passed across agents
export interface MultiAgentContext {
  veramoAgent: IAgent
  subjectDid: string
  baseCredentialPayload?: ICreateVerifiableCredentialArgs['credential']
  researchFindings: ResearchFinding[]
  consensusClaims: ConsensusClaim[]
  partialSignatures: PartialSignature[]
  ownershipProofs: OwnershipProof[]
  aggregatedCredential?: VerifiableCredential
}

export interface ResearchFinding {
  agentId: string
  claimDraft: string
  rationale: string
}

export interface ConsensusClaim {
  claim: string
  supportingFindings: ResearchFinding[]
}

export interface PartialSignature {
  issuerDid: string
  signatureHex: string
  payload: ICreateVerifiableCredentialArgs['credential']
}

export interface OwnershipProof {
  issuerDid: string
  proof: unknown
}

export const multiAgentContext: MultiAgentContext = {
  veramoAgent,
  subjectDid: 'did:example:subject',
  researchFindings: [],
  consensusClaims: [],
  partialSignatures: [],
  ownershipProofs: [],
}

export class CollaborativeAIAgent {
  constructor(
    public readonly id: string,
    protected readonly model: ChatOpenAI,
    protected readonly prompt: ChatPromptTemplate,
  ) {}

  protected async generateResponse(variables: Record<string, unknown>): Promise<string> {
    const message = await this.prompt.format(variables)
    const response = await this.model.invoke(message)
    return response.content.toString().trim()
  }
}

// Establishes DIDs, keys, and the base credential payload.
export class IdentityAgent extends CollaborativeAIAgent {
  async bootstrap(context: MultiAgentContext, credentialSubject: Record<string, unknown>): Promise<void> {
    const identifier = await context.veramoAgent.didManagerCreate()
    const issuanceDate = new Date().toISOString()
    context.baseCredentialPayload = {
      issuer: { id: identifier.did },
      multi_issuers: [identifier.did],
      issuanceDate,
      type: ['VerifiableCredential', 'CollaborativeAuthorizationCredential'],
      credentialSubject: { id: context.subjectDid, ...credentialSubject },
    }
  }
}

// Produces independent research findings with an LLM.
export class ResearchAgent extends CollaborativeAIAgent {
  async research(context: MultiAgentContext, topic: string): Promise<ResearchFinding> {
    const claimDraft = await this.generateResponse({ topic })
    const finding: ResearchFinding = {
      agentId: this.id,
      claimDraft,
      rationale: `Evidence and reasoning produced by ${this.id} for ${topic}.`,
    }
    context.researchFindings.push(finding)
    return finding
  }
}

// Consolidates findings into consensus claims.
export class ConsensusAgent extends CollaborativeAIAgent {
  async buildConsensus(context: MultiAgentContext): Promise<ConsensusClaim[]> {
    const serializedFindings = context.researchFindings
      .map((finding) => `- ${finding.agentId}: ${finding.claimDraft}`)
      .join('\n')
    const consensusText = await this.generateResponse({ findings: serializedFindings })
    const consensus: ConsensusClaim = {
      claim: consensusText,
      supportingFindings: [...context.researchFindings],
    }
    context.consensusClaims.push(consensus)
    return context.consensusClaims
  }
}

// Delegates BLS signing to simulation.ts
export class BLSSignerAgent {
  constructor(public readonly id: string, private readonly keyRef: string) {}

  async sign(context: MultiAgentContext): Promise<PartialSignature> {
    if (!context.baseCredentialPayload) {
      throw new Error('Base credential payload missing')
    }

    const signatureData = await signMultiIssuedVerifiableCredential({
      credential: context.baseCredentialPayload,
      proofFormat: 'sign-bls-multi-signature',
      keyRef: this.keyRef,
    })

    const partial: PartialSignature = {
      issuerDid: context.baseCredentialPayload.issuer?.id ?? this.id,
      signatureHex: signatureData.signatureHex ?? signatureData.signature,
      payload: context.baseCredentialPayload,
    }

    context.partialSignatures.push(partial)
    return partial
  }
}

// Produces DID-based ownership proofs through Veramo.
export class ProofOfOwnershipAgent extends CollaborativeAIAgent {
  async attestOwnership(context: MultiAgentContext): Promise<OwnershipProof> {
    if (!context.baseCredentialPayload) {
      throw new Error('Base credential payload missing')
    }

    const vc = await context.veramoAgent.createVerifiableCredential({
      credential: context.baseCredentialPayload,
      proofFormat: 'jwt',
    })

    const proof: OwnershipProof = {
      issuerDid: context.baseCredentialPayload.issuer?.id ?? this.id,
      proof: vc.proof,
    }

    context.ownershipProofs.push(proof)
    return proof
  }
}

// Aggregates signatures and proofs into the final VC using simulation.ts helpers.
export class AggregatorAgent extends CollaborativeAIAgent {
  async aggregate(context: MultiAgentContext): Promise<VerifiableCredential> {
    if (!context.baseCredentialPayload) {
      throw new Error('Base credential payload missing')
    }

    const aggregatedSignature = await aggregatePartialSignatures(context.partialSignatures)
    const credentialWithClaims = {
      ...context.baseCredentialPayload,
      claims: context.consensusClaims.map((c) => c.claim),
    }

    const finalCredential = await finalizeMultiIssuedCredential({
      credential: credentialWithClaims,
      aggregatedSignature,
      ownershipProofs: context.ownershipProofs,
    })

    context.aggregatedCredential = finalCredential
    return finalCredential
  }
}

// Prompt factories
export const defaultResearchPrompt = ChatPromptTemplate.fromTemplate(
  'You are {agentId}. Provide a concise claim for the topic: {topic}.',
)

export const defaultConsensusPrompt = ChatPromptTemplate.fromTemplate(
  'Summarize the following findings into a single agreed claim:\n{findings}',
)

export function createOpenAIModel(apiKey?: string): ChatOpenAI {
  return new ChatOpenAI({
    apiKey,
    model: 'gpt-4o-mini',
    temperature: 0.2,
  })
}

