import { agent } from '../../veramo/setup.js';
/** Verify a standard VP (jwt/lds) */
export async function verifyVP(vp) {
    const result = await agent.verifyPresentation({ presentation: vp });
    console.log('Verifiable Presentation Verification Result:', result.verified);
    return result;
}
/** Verify a multi-holder VP with aggregated BLS signature (no PoO) */
export async function verifyMultiSignatureVP(vp) {
    const result = await agent.verifyMultisignaturePresentation({ presentation: vp });
    console.log('Multi-Holder BLS VP Verification Result:', result);
    return result;
}
/** Verify a multi-holder VP with PoO + aggregated BLS signature */
export async function verifyPoOVP(vp) {
    const result = await agent.verifyProofOfOwnershipMultisignaturePresentation({ presentation: vp });
    console.log('Multi-Holder PoO+BLS VP Verification Result:', result);
    return result;
}
/** Verify all VCs embedded in a VP. */
export async function verifyVCsFromVP(vp) {
    const creds = Array.isArray(vp.verifiableCredential) ? vp.verifiableCredential : [];
    if (creds.length === 0) {
        throw new Error('VP has no embedded verifiableCredential entries');
    }
    for (const cred of creds) {
        const vc = cred;
        try {
            const r = await agent.verifyCredential({ credential: vc });
            if (!r.verified)
                return false;
        }
        catch {
            return false;
        }
    }
    return true;
}
export async function verifyVCs(vcs) {
    if (vcs.length === 0) {
        throw new Error('No VCs provided');
    }
    for (const vc of vcs) {
        try {
            const r = await agent.verifyCredential({ credential: vc });
            if (!r.verified)
                return false;
        }
        catch {
            return false;
        }
    }
    return true;
}
