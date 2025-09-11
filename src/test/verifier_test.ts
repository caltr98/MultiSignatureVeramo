import { VerifiablePresentation, VerifiableCredential } from '@veramo/core'
import { agent } from '../veramo/setup.js'

/**
 * Verifies a standard Verifiable Presentation.
 * @param vp The Verifiable Presentation to verify.
 * @returns Verification result from Veramo.
 */
export async function verifyVP(
    vp: VerifiablePresentation,
): Promise<any> {
    try {
        const result = await agent.verifyPresentation({ presentation: vp })
        console.log('Verifiable Presentation Verification Result:', result.verified)
        return result
    } catch (error) {
        console.error('Error verifying VP:', error)
        throw error
    }
}



/**
 * Verifies a multi-issuer Verifiable Credential with BLS aggregated signature.
 * @param vc The Verifiable Credential to verify.
 * @returns Verification result from Veramo.
 */
export async function verifyMultiSignatureVC(
    vc: VerifiableCredential,
): Promise<any> {
    try {
        const result = await agent.verifyProofOfOwnershipMultisignatureCredential({
            credential: {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                type: ["VerifiableCredential", "aggregated-bls-multi-signature"],
                multi_issuers: vc.multi_issuers,
                credentialSubject: vc.credentialSubject,
                proof: vc.proof,
                aggregated_bls_public_key: vc.aggregated_bls_public_key,
            },
        })
        console.log('Multi-Issuer BLS VC Verification Result:', result)
        return result
    } catch (error) {
        console.error('Error verifying multi-signature VC:', error)
        throw error
    }
}
