import { agent } from '../veramo/setup_eip712.js';
export async function verifyVP(vp) {
    const result = await agent.verifyPresentation({ presentation: vp });
    console.log('Verifiable Presentation Verification Result:', result.verified);
    return result;
}
export async function verifySingleIssuerVC(vc) {
    // `verifyCredentialEIP712` returns a boolean in @veramo/credential-eip712.
    const verified = (await agent.verifyCredentialEIP712({ credential: vc }));
    return { verified };
}
/**
 * Verifies each VC inside the VP using EIP712 verification.
 * Note: EIP712 VC verification depends on DID resolution containing an Ethereum address.
 * If verification fails, we throw with a helpful error instead of retrying indefinitely.
 */
export async function verifyAllVCsInVP(vp, timings) {
    const results = [];
    if (!vp.verifiableCredential || !Array.isArray(vp.verifiableCredential)) {
        return results;
    }
    const label = `Verify VCs`;
    if (timings)
        timings[label] = 0;
    for (let i = 0; i < vp.verifiableCredential.length; i++) {
        const vc = vp.verifiableCredential[i];
        const start = performance.now();
        const verified = (await agent.verifyCredentialEIP712({ credential: vc }));
        const end = performance.now();
        if (timings)
            timings[label] = (timings[label] ?? 0) + (end - start);
        if (!verified) {
            const issuer = vc?.issuer?.id ?? vc?.issuer;
            throw new Error(`EIP712 VC[${i}] verification failed (issuer=${issuer}). ` +
                `Ensure DID resolution works for the issuer DID and that issuance used the issuer keyRef.`);
        }
        results.push({ verified: true, index: i });
    }
    return results;
}
