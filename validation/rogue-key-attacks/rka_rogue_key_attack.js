import canonicalize from 'canonicalize';
import { generatePayloadToSign, signPayloadWithIssuers, createProofsOfOwnershipPerIssuer, aggregateBlsKeys, } from '../../src/test/issuers_test.js';
import { setup_bls_agents, cleanup } from '../../src/test/enviroment_setup.js';
import { generateProofOfOwnershipMultiIssuerVerifiableCredentialBls, verifyCredentialProofOfOwnershipMultiSignatureBls, } from '../../src/plugins/bls-extend-credential-w3c/src/bls-credentials.js';
import { agent } from '../../src/veramo/setup.js';
import { bls12_381 as bls } from '@noble/curves/bls12-381';
import { bytesToHex } from '@noble/hashes/utils';
const strip0x = (hex) => (hex.startsWith('0x') ? hex.slice(2) : hex);
const pointFromHex = (hex) => bls.G1.ProjectivePoint.fromHex(strip0x(hex));
const pointToHex = (p) => '0x' + bytesToHex(p.toRawBytes(true));
// CLI args to tweak size of the test payload
function parseArg(name, def) {
    const i = process.argv.indexOf(`--${name}`);
    if (i !== -1 && process.argv[i + 1]) {
        const val = parseInt(process.argv[i + 1]);
        if (!isNaN(val))
            return val;
    }
    return def;
}
const CLAIMS = parseArg('claims', 2);
const VALUE_SIZE = parseArg('size', 32);
async function getEthKeyKidForDid(did) {
    const identifier = await agent.didManagerGet({ did });
    const ethKey = identifier.keys.find((k) => k.type === 'Secp256k1' || k.meta?.alg === 'eth_signMessage');
    if (!ethKey)
        throw new Error(`No Secp256k1 key found for DID ${did}`);
    return ethKey.kid;
}
async function buildLegitCredential(issuers, holderDid, blsBackend) {
    // Honest flow: aggregate honest BLS keys, sign payload, attach PoO, then verify
    const aggregatedKey = await aggregateBlsKeys(issuers.map((i) => i.bls_pub_key));
    const payload = await generatePayloadToSign(issuers, holderDid, aggregatedKey, CLAIMS, VALUE_SIZE);
    const { signatures } = await signPayloadWithIssuers(payload, issuers);
    const proofsOfOwnership = await createProofsOfOwnershipPerIssuer(issuers, holderDid, payload);
    const vc = await generateProofOfOwnershipMultiIssuerVerifiableCredentialBls(payload, proofsOfOwnership, signatures, undefined, blsBackend);
    const verification = await verifyCredentialProofOfOwnershipMultiSignatureBls(vc, { agent }, undefined, blsBackend);
    return { vc, verification };
}
async function attemptRogueKeyAttack(honest, malicious, holderDid, blsBackend) {
    // Single attacker performs the rogue-key attack
    const attacker = malicious[0];
    const issuersWithHonestFirst = [honest, attacker];
    // Step 1: forge rogue BLS key so PK_honest + PK_rogue = PK_fake (attacker knows only SK_fake)
    const { aggPkHex: fakeAggPkHex, rogueSk } = (() => {
        const victimPoints = [pointFromHex(honest.bls_pub_key)];
        const fakeSk = bls.utils.randomPrivateKey();
        const fakePkPoint = pointFromHex(bytesToHex(bls.getPublicKey(fakeSk)));
        const roguePkPoint = victimPoints.reduce((acc, p) => acc.add(p.negate()), fakePkPoint);
        const aggregatedPkPoint = victimPoints.reduce((acc, p) => acc.add(p), roguePkPoint);
        return { aggPkHex: pointToHex(aggregatedPkPoint), rogueSk: fakeSk };
    })();
    // Step 2: build payload using the fake aggregate key (verifier thinks honest+attacker are included)
    const payload = await generatePayloadToSign(issuersWithHonestFirst, holderDid, fakeAggPkHex, CLAIMS, VALUE_SIZE);
    const canonical = canonicalize(payload);
    if (!canonical)
        throw new Error('Failed to canonicalize payload');
    // Step 3: attacker signs once with SK_fake; aggregate PK will make it look like both signed
    const rogueSignature = bytesToHex(await bls.sign(new TextEncoder().encode(canonical), rogueSk));
    // Step 4: reuse an old PoO from a previous VC (different claims) for the honest issuer
    const stalePayloadForHonest = {
        ...payload,
        credentialSubject: {
            ...payload.credentialSubject,
            stale_marker: 'reused-proof', // ensure payload differs from the current one
        },
    };
    const staleCanonical = canonicalize(stalePayloadForHonest);
    if (!staleCanonical)
        throw new Error('Failed to canonicalize stale payload for PoO reuse');
    const honestEthKid = await getEthKeyKidForDid(honest.did);
    const reusedPoOForHonest = await agent.keyManagerSign({
        keyRef: honestEthKid,
        data: JSON.stringify(staleCanonical),
        algorithm: 'eth_signMessage',
        encoding: 'utf-8',
    });
    const maliciousPoOs = await createProofsOfOwnershipPerIssuer([attacker], holderDid, payload);
    const forgedPoOs = [reusedPoOForHonest, ...maliciousPoOs];
    // Step 5: assemble forged VC and run verification (expected fail if defenses work)
    const rogueVc = await generateProofOfOwnershipMultiIssuerVerifiableCredentialBls(payload, forgedPoOs, ['0x' + rogueSignature], undefined, blsBackend);
    const verification = await verifyCredentialProofOfOwnershipMultiSignatureBls(rogueVc, { agent }, undefined, blsBackend);
    return { rogueVc, verification };
}
async function main() {
    const blsBackend = process.env.VERAMO_BLS_BACKEND ?? undefined;
    const [honest] = await setup_bls_agents(1);
    const malicious = await setup_bls_agents(2);
    const holder = (await setup_bls_agents(1))[0];
    console.log('--- Honest issuance baseline (expected: verified=true) ---');
    const honestRun = await buildLegitCredential([honest, ...malicious], holder.did, blsBackend);
    console.log(honestRun.verification);
    console.log('\n--- Rogue-key attempt (expected: verified=false) ---');
    const rogueRun = await attemptRogueKeyAttack(honest, malicious, holder.did, blsBackend);
    console.log(rogueRun.verification);
}
main()
    .catch((err) => {
    console.error(err);
    process.exit(1);
})
    .finally(async () => {
    await cleanup();
});
