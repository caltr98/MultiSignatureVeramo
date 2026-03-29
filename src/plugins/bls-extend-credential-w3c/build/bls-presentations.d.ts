import { DIDResolutionOptions, IVerifyResult, VerifierAgentContext, VerifiablePresentation } from '@veramo/core-types';
import { MultiIssuerVerifiablePresentation, ProofOfOwnershipMultiIssuerVerifiablePresentation } from './action-handler.js';
type BlsBackend = 'chainsafe' | 'noble';
export declare function verifyPresentationProofOfOwnershipMultiSignatureBls(presentation: ProofOfOwnershipMultiIssuerVerifiablePresentation, context: VerifierAgentContext, resolutionOptions?: DIDResolutionOptions, blsBackend?: BlsBackend): Promise<IVerifyResult & {
    timings?: Record<string, number>;
}>;
export declare function aggregateMultiSignatureVerifiablePresentationBls(presentation: any, options: {
    alg: string;
    did: string;
    signer: (data: Uint8Array) => Promise<string>;
}, list_of_signatures: string[], settings?: {
    resolutionOptions?: DIDResolutionOptions & {
        publicKeyFormat?: string;
    };
    fetchRemoteContexts?: boolean;
}): Promise<any>;
export declare function generateProofOfOwnershipMultiIssuerVerifiablePresentationBls(presentation: any, proofs_of_ownership: any, list_of_signatures: string[], settings?: string[], blsBackend?: BlsBackend): Promise<any>;
export declare function signMultiSignatureVerifiablePresentationBls(presentation: any, options: {
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
export declare function createVerifiablePresentationBls(presentation: any, options: {
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
export declare function verifyPresentationBls(presentation: VerifiablePresentation, context: VerifierAgentContext, resolutionOptions?: DIDResolutionOptions, blsBackend?: BlsBackend): Promise<IVerifyResult>;
/**
 * Verify a BLS-signed Verifiable Credential
 */
export declare function verifyPresentationMultiSignatureBls(presentation: MultiIssuerVerifiablePresentation, context: VerifierAgentContext, resolutionOptions?: DIDResolutionOptions, blsBackend?: BlsBackend): Promise<IVerifyResult>;
export {};
