import { DIDResolutionOptions, VerifiableCredential, IVerifyResult, VerifierAgentContext } from '@veramo/core-types';
import { MultiIssuerVerifiableCredential, ProofOfOwnershipMultiIssuerVerifiableCredential } from './action-handler.js';
type BlsBackend = 'chainsafe' | 'noble';
export declare function verifyCredentialProofOfOwnershipMultiSignatureBls(credential: ProofOfOwnershipMultiIssuerVerifiableCredential, context: VerifierAgentContext, resolutionOptions?: DIDResolutionOptions, blsBackend?: BlsBackend): Promise<IVerifyResult & {
    timings?: Record<string, number>;
}>;
export declare function aggregateMultiSignatureVerifiableCredentialBls(credential: any, options: {
    alg: string;
    did: string;
    signer: (data: Uint8Array) => Promise<string>;
}, list_of_signatures: string[], settings?: {
    resolutionOptions?: DIDResolutionOptions & {
        publicKeyFormat?: string;
    };
    fetchRemoteContexts?: boolean;
}): Promise<any>;
export declare function generateProofOfOwnershipMultiIssuerVerifiableCredentialBls(credential: any, proofs_of_ownership: any, list_of_signatures: string[], settings?: string[], blsBackend?: BlsBackend): Promise<any>;
export declare function signMultiSignatureVerifiableCredentialBls(credential: any, options: {
    alg: string;
    did: string;
    signer: (data: Uint8Array) => Promise<string>;
}, settings?: {
    resolutionOptions?: DIDResolutionOptions & {
        publicKeyFormat?: string;
    };
    fetchRemoteContexts?: boolean;
}): Promise<any>;
/**
* Create a BLS-signed Verifiable Credential
*/
export declare function createVerifiableCredentialBls(credential: any, options: {
    alg: string;
    did: string;
    signer: (data: Uint8Array) => Promise<string>;
}, settings?: {
    resolutionOptions?: DIDResolutionOptions & {
        publicKeyFormat?: string;
    };
    fetchRemoteContexts?: boolean;
}): Promise<any>;
/**
 * Verify a BLS-signed Verifiable Credential
 */
export declare function verifyCredentialBls(credential: VerifiableCredential, context: VerifierAgentContext, resolutionOptions?: DIDResolutionOptions, blsBackend?: BlsBackend): Promise<IVerifyResult>;
/**
 * Verify a BLS-signed Verifiable Credential
 */
export declare function verifyCredentialMultiSignatureBls(credential: MultiIssuerVerifiableCredential, context: VerifierAgentContext, resolutionOptions?: DIDResolutionOptions, blsBackend?: BlsBackend): Promise<IVerifyResult>;
export {};
