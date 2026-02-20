import process from 'process'
import OpenAI from 'openai'

// ==== EXISTING INTERNAL CALLS (NO HTTP / NO API SERVER) ====
import { singleActorSetup } from './single_actor_setup.js'
import {
    aggregateBlsKeys,
    IndividualBlsVPSignatures,
    buildVPPayloadWithAggKey,
    createMultiHolderPresentation,
    createPoO,
} from '../src/server-demo/actors/holder_test.js'

// ================= TYPES =================

type AgentOpinion = {
    did: string
    answer: string
    confidence: number
}

type Personality = {
    bias: 'safety' | 'efficiency' | 'policy' | 'environment'
    style: 'cautious' | 'assertive' | 'analytical'
    stubbornness: number // 0–1
}

type AIAgentState = {
    name: string
    did: string
    kid_bls: string
    bls_pub_key: string
    kid_eth: string
    personality: Personality
}

// ================= UTIL =================

function randomOf<T>(arr: T[]): T {
    return arr[Math.floor(Math.random() * arr.length)]
}

function randomPersonality(): Personality {
    return {
        bias: randomOf(['safety', 'efficiency', 'policy', 'environment']),
        style: randomOf(['cautious', 'assertive', 'analytical']),
        stubbornness: Math.round(Math.random() * 100) / 100,
    }
}

// ================= AI ISSUER =================

class AIIssuerAgent {
    readonly client: OpenAI
    state!: AIAgentState

    constructor(public readonly name: string) {
        const apiKey = process.env.OPENAI_API_KEY
        if (!apiKey) {
            throw new Error('Set OPENAI_API_KEY to use the AI issuer agents')
        }

        this.client = new OpenAI({ apiKey })
    }

    async setup() {
        const a = await singleActorSetup(this.name)
        this.state = {
            name: this.name,
            did: a.did,
            kid_bls: a.kid_bls,
            bls_pub_key: a.bls_pub_key,
            kid_eth: a.kid_eth,
            personality: randomPersonality(),
        }
    }

    async deliberate(
        question: string,
        peers: AgentOpinion[] = [],
    ): Promise<AgentOpinion> {
        const p = this.state.personality

        const systemPrompt = `
You are an AI authority with:
- Priority bias: ${p.bias}
- Reasoning style: ${p.style}
- Stubbornness: ${p.stubbornness}

If peer opinions differ and stubbornness < 0.7,
you may revise your stance.

Respond with a concise final answer only.
        `.trim()

        const peerAnswers =
            peers.map(o => `- ${o.answer}`).join('\n') || '(none)'

        const userPrompt = `
Question: ${question}

Peer answers so far:
${peerAnswers}

Your answer:
        `.trim()

        const res = await this.client.chat.completions.create({
            model: 'gpt-4o-mini',
            temperature: 0.3,
            messages: [
                { role: 'system', content: systemPrompt },
                { role: 'user', content: userPrompt },
            ],
        })

        const answer =
            res.choices[0]?.message?.content?.trim() ||
            'No answer produced.'

        return {
            did: this.state.did,
            answer,
            confidence: Math.round((1 - p.stubbornness) * 100) / 100,
        }
    }

    async signVP(presentation: any) {
        return IndividualBlsVPSignatures(
            presentation,
            this.state.did,
            this.state.kid_bls,
        )
    }

    async signPoO(payloadToSign: string) {
        return createPoO(
            this.state.did,
            this.state.kid_eth,
            payloadToSign,
        )
    }
}

// ================= CONSENSUS =================

function selectFinalAnswer(opinions: AgentOpinion[]): string {
    const votes = new Map<string, number>()
    for (const o of opinions) {
        votes.set(o.answer, (votes.get(o.answer) || 0) + 1)
    }
    return [...votes.entries()].sort((a, b) => b[1] - a[1])[0][0]
}

// ================= MAIN =================

async function main() {
    const [, , nStr, ...questionParts] = process.argv

    if (!nStr || questionParts.length === 0) {
        console.error('Usage: ts-node multi_ai_committee.ts <N> "<question>"')
        process.exit(1)
    }

    const N = Number(nStr)
    const question = questionParts.join(' ').trim()

    if (Number.isNaN(N) || N <= 0) {
        throw new Error('N must be a positive integer')
    }

    console.log(`\n▶ Creating committee of ${N} AI issuers`)
    console.log(`▶ Question: "${question}"\n`)

    // 1) Setup agents
    const agents = Array.from({ length: N }, (_, i) =>
        new AIIssuerAgent(`ai_issuer_${i + 1}`),
    )

    await Promise.all(agents.map(a => a.setup()))

    agents.forEach(a => {
        const p = a.state.personality
        console.log(
            `• ${a.state.name} | ${p.bias}, ${p.style}, stubborn=${p.stubbornness}`,
        )
    })

    // 2) Multi-round deliberation
    let opinions: AgentOpinion[] = []

    for (let round = 0; round < 2; round++) {
        console.log(`\n🧠 Deliberation round ${round + 1}`)
        opinions = await Promise.all(
            agents.map(a => a.deliberate(question, opinions)),
        )

        opinions.forEach(o => {
            const a = agents.find(x => x.state.did === o.did)!
            console.log(`- ${a.state.name}: ${o.answer}`)
        })
    }

    // 3) Consensus
    const finalAnswer = selectFinalAnswer(opinions)

    console.log('\n✅ Final agreed answer:\n')
    console.log(finalAnswer)

    // 4) Aggregate BLS keys
    const aggKey = await aggregateBlsKeys(
        agents.map(a => a.state.bls_pub_key),
    )

    // 5) Build VP payload
    const payload = buildVPPayloadWithAggKey(
        agents.map(a => a.state.did),
        aggKey,
        [],
        {
            type: 'CollectiveAIAnswer',
            question,
            answer: finalAnswer,
            issuers: agents.map(a => a.state.did),
            issuedAt: new Date().toISOString(),
        },
    )

    // 6) Signatures
    const blsSignatures: string[] = []
    const poos: string[] = []
    let payloadToSign = ''

    for (const agent of agents) {
        const { signature, payloadToSign: pts } =
            await agent.signVP(payload)
        payloadToSign ||= pts
        blsSignatures.push(signature)
    }

    // Optional PoO (can be disabled if needed)
    for (const agent of agents) {
        poos.push(await agent.signPoO(payloadToSign))
    }

    // 7) Create final VP
    const vp = await createMultiHolderPresentation(
        agents.map(a => a.state.did),
        true,
        aggKey,
        blsSignatures,
        poos,
        payload,
    )

    console.log('\n📦 Final Multi-Issuer Verifiable Presentation:\n')
    console.log(JSON.stringify(vp, null, 2))
}

main().catch(e => {
    console.error(e)
    process.exit(1)
})
