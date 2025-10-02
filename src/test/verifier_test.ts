import { VerifiablePresentation, VerifiableCredential } from '@veramo/core'
import { agent } from '../veramo/setup.js'

/** Your existing standard VP verifier (unchanged) */
export async function verifyVP(vp: VerifiablePresentation): Promise<any> {
    try {
        const result = await agent.verifyPresentation({ presentation: vp })
        console.log('Verifiable Presentation Verification Result:', result.verified)
        return result
    } catch (error) {
        console.error('Error verifying VP:', error)
        throw error
    }
}

/** Your existing multi-issuer VC verifier (unchanged) */
export async function verifyMultiSignatureVC(vc: VerifiableCredential): Promise<any> {
    try {
        const result = await agent.verifyProofOfOwnershipMultisignatureCredential({
            credential: {
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                type: ['VerifiableCredential', 'aggregated-bls-multi-signature'],
                multi_issuers: (vc as any).multi_issuers, // field comes from your custom plugin shape
                credentialSubject: vc.credentialSubject,
                proof: vc.proof,
                aggregated_bls_public_key: (vc as any).aggregated_bls_public_key,
            },
        })
        console.log('Multi-Issuer BLS VC Verification Result:', result)
        return result
    } catch (error) {
        console.error('Error verifying multi-signature VC:', error)
        throw error
    }
}

/** Narrow types matching your custom plugin’s VP shape */
export interface MultiHolderVP extends VerifiablePresentation {
    multi_holders: string[]
}
export interface PoOMultiHolderVP extends MultiHolderVP {
    aggregated_bls_public_key: string
}

/** Verify a multi-holder VP with aggregated BLS signature (no PoO) */
export async function verifyMultiSignatureVP(vp: MultiHolderVP): Promise<any> {
    try {
        const result = await agent.verifyMultisignaturePresentation({
            presentation: vp,
        } as any)
        console.log('Multi-Holder BLS VP Verification Result:', result)
        return result
    } catch (error) {
        console.error('Error verifying multi-holder BLS VP:', error)
        throw error
    }
}

/** Verify a multi-holder VP with PoO + aggregated BLS signature */
export async function verifyPoOVP(vp: PoOMultiHolderVP): Promise<any> {
    try {
        const result = await agent.verifyProofOfOwnershipMultisignaturePresentation({
            presentation: vp,
        } as any)
        console.log('Multi-Holder PoO+BLS VP Verification Result:', result)
        return result
    } catch (error) {
        console.error('Error verifying multi-holder PoO+BLS VP:', error)
        throw error
    }
}
