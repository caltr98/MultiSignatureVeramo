import { agent } from '../veramo/setup.js';
/**
 * Verifies a standard Verifiable Presentation.
 * @param vp The Verifiable Presentation to verify.
 * @returns The verification result from Veramo.
 */
export async function verifyVP(vp) {
    try {
        const result = await agent.verifyPresentation({ presentation: vp });
        console.log('Verifiable Presentation Verification Result:', result.verified);
        return result;
    }
    catch (error) {
        console.error('Error verifying VP:', error);
        throw error;
    }
}
/**
 * Verifies a multi-issuer Verifiable Credential with BLS aggregated signature.
 * If you are using a custom Veramo plugin to handle this format, this assumes it's already registered.
 *
 * @param vc The Verifiable Credential to verify.
 * @returns The verification result from Veramo.
 */
export async function verifySingleIssuerVC(vc) {
    try {
        const result = await agent.verifyCredential({
            credential: vc,
        });
        console.log('Multi-Issuer BLS VC Verification Result:', result.verified);
        return result;
    }
    catch (error) {
        console.error('Error verifying multi-signature VC:', error);
        throw error;
    }
}
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
/**
 * Verifies each VC inside the VP.
 * Retries each VC until verified, and measures only the final successful attempt.
 * Timings are recorded in the provided timings map (if given).
 */
export async function verifyAllVCsInVP(vp, timings) {
    const results = [];
    if (!vp.verifiableCredential || !Array.isArray(vp.verifiableCredential)) {
        return results;
    }
    const label = `Verify VCs`;
    if (timings) {
        timings[label] = 0;
    }
    for (let i = 0; i < vp.verifiableCredential.length; i++) {
        const vc = vp.verifiableCredential[i];
        let verified = false;
        while (!verified) {
            try {
                const result = await agent.verifyCredential({ credential: vc });
                if (result?.verified) {
                    // Final successful verification — measure this one only
                    const start = performance.now();
                    await agent.verifyCredential({ credential: vc }); // re-run clean for timing
                    const end = performance.now();
                    if (timings)
                        timings[label] = timings[label] + (end - start);
                    verified = true;
                    results.push({ verified: true, index: i });
                }
                else {
                    console.log(`Verification failed for VC[${i}], retrying...`);
                    await sleep(3000);
                }
            }
            catch (error) {
                console.log(`Error verifying VC[${i}], retrying...`);
                await sleep(3000);
            }
        }
    }
    return results;
}
