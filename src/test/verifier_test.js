import { agent } from '../veramo/setup.js';
/** Your existing standard VP verifier (unchanged) */
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
/** Your existing multi-issuer VC verifier (unchanged) */
export async function verifyMultiSignatureVC(vc) {
    try {
        const result = await agent.verifyProofOfOwnershipMultisignatureCredential({
            credential: {
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                type: ['VerifiableCredential', 'aggregated-bls-multi-signature'],
                multi_issuers: vc.multi_issuers, // field comes from your custom plugin shape
                credentialSubject: vc.credentialSubject,
                proof: vc.proof,
                aggregated_bls_public_key: vc.aggregated_bls_public_key,
            },
        });
        console.log('Multi-Issuer BLS VC Verification Result:', result);
        return result;
    }
    catch (error) {
        console.error('Error verifying multi-signature VC:', error);
        throw error;
    }
}
/** Verify a multi-issuer VC with aggregated BLS signature (NO Proofs-of-Ownership). */
export async function verifyMultiSignatureVCNoPoO(vc) {
    try {
        const result = await agent.verifyMultisignatureCredential({
            credential: {
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                type: ['VerifiableCredential', 'aggregated-bls-multi-signature'],
                multi_issuers: vc.multi_issuers,
                credentialSubject: vc.credentialSubject,
                proof: vc.proof,
            },
        });
        console.log('Multi-Issuer (no PoO) BLS VC Verification Result:', result);
        return result;
    }
    catch (error) {
        console.error('Error verifying multi-signature VC (no PoO):', error);
        throw error;
    }
}
/** Verify a multi-holder VP with aggregated BLS signature (no PoO) */
export async function verifyMultiSignatureVP(vp) {
    try {
        const result = await agent.verifyMultisignaturePresentation({
            presentation: vp,
        });
        console.log('Multi-Holder BLS VP Verification Result:', result);
        return result;
    }
    catch (error) {
        console.error('Error verifying multi-holder BLS VP:', error);
        throw error;
    }
}
/** Verify a multi-holder VP with PoO + aggregated BLS signature */
export async function verifyPoOVP(vp) {
    try {
        const result = await agent.verifyProofOfOwnershipMultisignaturePresentation({
            presentation: vp,
        });
        console.log('Multi-Holder PoO+BLS VP Verification Result:', result);
        return result;
    }
    catch (error) {
        console.error('Error verifying multi-holder PoO+BLS VP:', error);
        throw error;
    }
}
