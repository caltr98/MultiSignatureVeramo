import process from 'process';
import { ChatOpenAI } from '@langchain/openai';
import { ChatPromptTemplate } from '@langchain/core/prompts';
import { RunnableSequence } from '@langchain/core/runnables';
// ==== EXISTING INTERNAL CALLS (NO HTTP / NO API SERVER) ====
import { singleActorSetup } from './single_actor_setup.js';
import { aggregateBlsKeys, IndividualBlsVPSignatures, buildVPPayloadWithAggKey, createMultiHolderPresentation, createPoO, } from './actors/holder_test.js';
// ================= UTIL =================
function randomOf(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
}
function randomPersonality() {
    return {
        bias: randomOf(['safety', 'efficiency', 'policy', 'environment']),
        style: randomOf(['cautious', 'assertive', 'analytical']),
        stubbornness: Math.round(Math.random() * 100) / 100,
    };
}
// ================= AI ISSUER =================
class AIIssuerAgent {
    name;
    llm;
    state;
    constructor(name) {
        this.name = name;
        this.llm = new ChatOpenAI({
            model: 'gpt-4o-mini',
            temperature: 0.3,
            apiKey: "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",
        });
    }
    async setup() {
        const a = await singleActorSetup(this.name);
        this.state = {
            name: this.name,
            did: a.did,
            kid_bls: a.kid_bls,
            bls_pub_key: a.bls_pub_key,
            kid_eth: a.kid_eth,
            personality: randomPersonality(),
        };
    }
    async deliberate(question, peers = []) {
        const p = this.state.personality;
        const prompt = ChatPromptTemplate.fromMessages([
            [
                'system',
                `
You are an AI authority with:
- Priority bias: ${p.bias}
- Reasoning style: ${p.style}
- Stubbornness: ${p.stubbornness}

If peer opinions differ and stubbornness < 0.7,
you may revise your stance.

Respond with a concise final answer only.
        `.trim(),
            ],
            [
                'human',
                `
Question: ${question}

Peer answers so far:
${peers.map(o => `- ${o.answer}`).join('\n') || '(none)'}

Your answer:
        `.trim(),
            ],
        ]);
        const chain = RunnableSequence.from([prompt, this.llm]);
        const res = await chain.invoke({});
        return {
            did: this.state.did,
            answer: String(res.content).trim(),
            confidence: Math.round((1 - p.stubbornness) * 100) / 100,
        };
    }
    async signVP(presentation) {
        return IndividualBlsVPSignatures(presentation, this.state.did, this.state.kid_bls);
    }
    async signPoO(payloadToSign) {
        return createPoO(this.state.did, this.state.kid_eth, payloadToSign);
    }
}
// ================= CONSENSUS =================
function selectFinalAnswer(opinions) {
    const votes = new Map();
    for (const o of opinions) {
        votes.set(o.answer, (votes.get(o.answer) || 0) + 1);
    }
    return [...votes.entries()].sort((a, b) => b[1] - a[1])[0][0];
}
// ================= MAIN =================
async function main() {
    const [, , nStr, ...questionParts] = process.argv;
    if (!nStr || questionParts.length === 0) {
        console.error('Usage: ts-node multi_ai_committee.ts <N> "<question>"');
        process.exit(1);
    }
    const N = Number(nStr);
    const question = questionParts.join(' ').trim();
    if (Number.isNaN(N) || N <= 0) {
        throw new Error('N must be a positive integer');
    }
    console.log(`\n▶ Creating committee of ${N} AI issuers`);
    console.log(`▶ Question: "${question}"\n`);
    // 1) Setup agents
    const agents = Array.from({ length: N }, (_, i) => new AIIssuerAgent(`ai_issuer_${i + 1}`));
    await Promise.all(agents.map(a => a.setup()));
    agents.forEach(a => {
        const p = a.state.personality;
        console.log(`• ${a.state.name} | ${p.bias}, ${p.style}, stubborn=${p.stubbornness}`);
    });
    // 2) Multi-round deliberation
    let opinions = [];
    for (let round = 0; round < 2; round++) {
        console.log(`\n🧠 Deliberation round ${round + 1}`);
        opinions = await Promise.all(agents.map(a => a.deliberate(question, opinions)));
        opinions.forEach(o => {
            const a = agents.find(x => x.state.did === o.did);
            console.log(`- ${a.state.name}: ${o.answer}`);
        });
    }
    // 3) Consensus
    const finalAnswer = selectFinalAnswer(opinions);
    console.log('\n✅ Final agreed answer:\n');
    console.log(finalAnswer);
    // 4) Aggregate BLS keys
    const aggKey = await aggregateBlsKeys(agents.map(a => a.state.bls_pub_key));
    // 5) Build VP payload
    const payload = buildVPPayloadWithAggKey(agents.map(a => a.state.did), aggKey, [], {
        type: 'CollectiveAIAnswer',
        question,
        answer: finalAnswer,
        issuers: agents.map(a => a.state.did),
        issuedAt: new Date().toISOString(),
    });
    // 6) Signatures
    const blsSignatures = [];
    const poos = [];
    let payloadToSign = '';
    for (const agent of agents) {
        const { signature, payloadToSign: pts } = await agent.signVP(payload);
        payloadToSign ||= pts;
        blsSignatures.push(signature);
    }
    // Optional PoO (can be disabled if needed)
    for (const agent of agents) {
        poos.push(await agent.signPoO(payloadToSign));
    }
    // 7) Create final VP
    const vp = await createMultiHolderPresentation(agents.map(a => a.state.did), true, aggKey, blsSignatures, poos, payload);
    console.log('\n📦 Final Multi-Issuer Verifiable Presentation:\n');
    console.log(JSON.stringify(vp, null, 2));
}
main().catch(e => {
    console.error(e);
    process.exit(1);
});
