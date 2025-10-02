// NEW ALL: LOGIC FOR BLS SIGNATURE ISSUING AND VERIFICATION

import {
    DIDResolutionOptions,
    VerifiableCredential,
    IVerifyResult,
    VerifierAgentContext,
    VerifiablePresentation
} from '@veramo/core-types'
import bls  from '@chainsafe/bls'
import canonicalize from 'canonicalize'
import { hexToBytes } from '@veramo/utils'
import {
    MultiIssuerVerifiableCredential, MultiIssuerVerifiablePresentation,
    ProofOfOwnershipMultiIssuerVerifiableCredential,
    ProofOfOwnershipMultiIssuerVerifiablePresentation
} from "./action-handler";
import {agent} from "../../../veramo/setup";
import { verifyMessage } from 'ethers';

import { ethers } from 'ethers'
import {sha256} from "@noble/hashes/sha256";
/**
 * Verify a BLS-MultiSignature Verifiable Credential then verify the proof of ownerships
 */
import {performance} from "node:perf_hooks";

/* ------------------- ADDED: optional attributes helper ------------------- */
function withOptionalAttributes<T extends Record<string, any>>(base: T, presentation: any): T {
    if (presentation && presentation.attributes !== undefined) {
        (base as any).attributes = presentation.attributes;
    }
    return base;
}
/* ------------------------------------------------------------------------ */

export async function verifyPresentationProofOfOwnershipMultiSignatureBls(
    presentation: ProofOfOwnershipMultiIssuerVerifiablePresentation,
    context: VerifierAgentContext,
    resolutionOptions?: DIDResolutionOptions
): Promise<IVerifyResult & { timings?: Record<string, number> }> {

    const timings: Record<string, number> = {};
    const proof = presentation.proof;

    if (!proof || !proof.type || !proof.signatureValue || !proof.ProofsOfOwnership) {
        return {
            verified: false,
            error: {
                message: 'Missing or malformed proof object',
                errorCode: 'invalid_proof',
            },
            timings,
        };
    }

    if (!Array.isArray(proof.verificationMethod)) {
        throw new Error('Single Signature Verification method is verifySignatureBls');
    }

    try {
        const t0 = performance.now();

        /* ------------ CHANGED: include attributes if present ------------ */
        const payloadToVerify = withOptionalAttributes({
            '@context': presentation['@context'],
            type: presentation['type'],
            multi_holders: presentation['multi_holders'],
            verifiableCredential: presentation.verifiableCredential,
            aggregated_bls_public_key: presentation['aggregated_bls_public_key'],
        }, presentation);
        /* ---------------------------------------------------------------- */

        const payload = canonicalize(payloadToVerify);
        if (!payload) throw new Error('Failed to canonicalize VC');

        const message = Uint8Array.from(Buffer.from(payload, 'utf-8'));

        // --- BLS Signature Verification ---
        const t1 = performance.now();
        const aggregatedPublicKey = bls.PublicKey.fromHex(presentation.aggregated_bls_public_key);
        const firstVerify = bls.verify(aggregatedPublicKey, message, hexToBytes(proof.signatureValue));
        console.log("first verify is"+firstVerify)
        const t2 = performance.now();
        timings["BLS Signature Verification"] = t2 - t1;

        if (!firstVerify) {
            return {
                verified: false,
                error: {
                    message: `Aggregate BLS verification of signature returned false`,
                    errorCode: 'invalid_signature',
                },
                timings,
            };
        }

        // --- DID Document Resolution ---
        const t3 = performance.now();
        const resolvedVMs = await Promise.all(
            proof.verificationMethod.map(async (method: string) => {
                const doc = await context.agent.resolveDid({
                    didUrl: method,
                    options: resolutionOptions,
                });

                const vm = doc?.didDocument?.verificationMethod?.find((v) =>
                    v.type === 'EcdsaSecp256k1RecoveryMethod2020' ? v : null
                );

                if (!vm) {
                    throw new Error(`Verification method ${method} not found in DID document`);
                }

                if (vm.type !== 'EcdsaSecp256k1RecoveryMethod2020') {
                    throw new Error(
                        `Invalid verification method type for ${method}: expected 'EcdsaSecp256k1RecoveryMethod2020' but got '${vm.type}'`
                    );
                }

                return vm;
            })
        );
        const t4 = performance.now();
        timings["DID DocumentS Resolution"] = t4 - t3;

        // --- Proof of Ownership Verification ---
        const t5 = performance.now();
        const signatures = proof.ProofsOfOwnership;

        if (signatures.length !== presentation.multi_holders.length) {
            throw new Error('Signatures and multi_holders arrays length mismatch');
        }

        for (let i = 0; i < presentation.multi_holders.length; i++) {
            const holderDID = presentation.multi_holders[i];
            const expectedAddress = holderDID.split(':').pop()?.toLowerCase();
            const signature = signatures[i];

            /* ------------ KEEP: no double stringify ------------ */
            const recoveredAddress = ethers.verifyMessage(payload, signature).toLowerCase();
            /* --------------------------------------------------- */

            if (recoveredAddress !== expectedAddress) {
                console.log("error is here: " + holderDID + " recovered: " + recoveredAddress + " - expected: " + expectedAddress);
                return {
                    verified: false,
                    error: {
                        message: `Address mismatch for issuer ${holderDID}`,
                        errorCode: 'invalid_signature',
                    },
                    timings,
                };
            }
        }

        const t6 = performance.now();
        timings["Proofs of Ownership Verification"] = t6 - t5;

        return {
            verified: true,
            timings,
        };

    } catch (e: any) {
        return {
            verified: false,
            error: {
                message: e.message,
                errorCode: e.code || 'verification_error',
            },
            timings,
        };
    }
}

// NEW: aggregate OF MULTI-SIGNATURE to make Multi Signature Verifiable Credential
export async function aggregateMultiSignatureVerifiablePresentationBls(
    presentation: any,
    options: {
        alg: string
        did: string
        signer: (data: Uint8Array) => Promise<string>
    },list_of_signatures: string[],
    settings?: {
        resolutionOptions?: DIDResolutionOptions & { publicKeyFormat?: string }
        fetchRemoteContexts?: boolean
    }
):Promise<any> {
    /* ------------ CHANGED: include attributes if present ------------ */
    const payloadToSign = canonicalize(withOptionalAttributes({
        '@context': presentation['@context'],
        type: presentation['type'],
        multi_holders: presentation['multi_holders'],
        verifiableCredential: presentation['verifiableCredential'],
    }, presentation));
    /* ---------------------------------------------------------------- */

    if (!payloadToSign) {
        throw new Error('Failed to canonicalize presentation payload')
    }

    if (!Array.isArray(list_of_signatures)) {
        throw new Error('Missing list_of_signatures for BLS aggregation')
    }

    //encode the signatures
    const encoded = new TextEncoder().encode(
        JSON.stringify({ signatures: list_of_signatures })
    )

    const signaturesAggregatedHex = await options.signer(encoded)

    const proof = {
        type: 'BlsMultiSignaturePisa',
        created: new Date().toISOString(),
        proofPurpose: 'assertionMethod',
        verificationMethod: presentation['multi_holders'],
        signatureValue: signaturesAggregatedHex,
    }

    return {
        ...presentation,
        proof
    }
}



// NEW: aggregate OF MULTI-SIGNATURE to make Multi Signature Verifiable Credential
export async function generateProofOfOwnershipMultiIssuerVerifiablePresentationBls(
    presentation: any, proofs_of_ownership:any,list_of_signatures: string[],
    settings?: string[]
):Promise<any> {

    // presentation is canonicalized as a whole, so attributes on presentation are already included
    const payLoad = canonicalize(presentation)
    if (!payLoad) {
        throw new Error('Failed to canonicalize presentation payload')
    }

    if (!Array.isArray(list_of_signatures)) {
        throw new Error('Missing list_of_signatures for BLS aggregation')
    }

    // convert signature strings from hex to objects signatures
    const signatureObjs = list_of_signatures.map(sigHex => bls.Signature.fromHex(sigHex))

    // aggregate signatures and turn into Hex
    const aggregatedSignature = Buffer.from(bls.aggregateSignatures(signatureObjs)).toString("hex")

    const proof = {
        type: 'ProofOfOwnershipBlsMultiSignaturePisa',
        proofPurpose: 'assertionMethod',
        verificationMethod: presentation['multi_holders'],
        ProofsOfOwnership: proofs_of_ownership,
        signatureValue: aggregatedSignature,
    }

    let issuanceDate = new Date().toISOString()
    return {
        ...presentation, issuanceDate,
        proof
    }
}

// NEW: SIGNING OF MULTI-SIGNATURE CREDENTIALS
export async function signMultiSignatureVerifiablePresentationBls(
    presentation: any,
    options: {
        alg: string
        did: string
        signer: (data: Uint8Array) => Promise<string>
    },
    settings?: {
        resolutionOptions?: DIDResolutionOptions & { publicKeyFormat?: string }
        fetchRemoteContexts?: boolean
    }
): Promise<any> {
    /* ------------ CHANGED: include attributes if present ------------ */
    const payloadToSign = canonicalize(withOptionalAttributes({
        '@context': presentation['@context'],
        type: presentation['type'],
        multi_holders: presentation['multi_holders'],
        verifiableCredential: presentation['verifiableCredential'],
        aggregated_bls_public_key: presentation['aggregated_bls_public_key'],
    }, presentation));
    /* ---------------------------------------------------------------- */

    if (!payloadToSign) {
        throw new Error('Failed to canonicalize presentation payload')
    }

    const message = Uint8Array.from(Buffer.from(payloadToSign, 'utf-8'));
    const signatureHex = await options.signer(message)

    const signatureData = {
        payloadToSign,
        signatureHex,
    }

    return {
        signatureData
    }
}


/**
 * Create a BLS-signed Verifiable Credential
 */
export async function createVerifiablePresentationBls(
    presentation: any,
    options: {
        alg: string
        did: string
        signer: (data: Uint8Array) => Promise<string>
    },
    settings?: {
        resolutionOptions?: DIDResolutionOptions & { publicKeyFormat?: string }
        fetchRemoteContexts?: boolean
    }
): Promise<any> {
    /* ------------ CHANGED: include attributes if present ------------ */
    const payloadToSign = canonicalize(withOptionalAttributes({
        '@context': presentation['@context'],
        type: presentation['type'],
        multi_holders: presentation['multi_holders'],
        issuanceDate: presentation['issuanceDate'],
        verifiableCredential: presentation['verifiableCredential'],
    }, presentation));
    /* ---------------------------------------------------------------- */

    if (!payloadToSign) {
        throw new Error('Failed to canonicalize presentation payload')
    }

    const signatureHex = await options.signer(Uint8Array.from(Buffer.from(payloadToSign, 'utf-8')))

    const proof = {
        type: 'BlsSignaturePisa',
        created: new Date().toISOString(),
        proofPurpose: 'assertionMethod',
        verificationMethod: `${options.did}#delegate-1`,
        signatureValue: signatureHex,
    }

    return {
        '@context': presentation['@context'],
        type: presentation['type'],
        multi_holders: presentation['multi_holders'],
        issuanceDate: presentation['issuanceDate'],
        verifiableCredential: presentation['verifiableCredential'],
        /* NOTE: attributes is part of the signed payload; it can be present at top-level presentation */
        proof: proof, // explicitly last
    }
}


/**
 * Verify a BLS-signed Verifiable Credential
 */
export async function verifyPresentationBls(
    presentation: VerifiablePresentation,
    context: VerifierAgentContext,
    resolutionOptions?: DIDResolutionOptions
): Promise<IVerifyResult> {
    const proof = presentation.proof
    if (!proof || !proof.type || !proof.signatureValue) {
        return {
            verified: false,
            error: {
                message: 'Missing or malformed proof object',
                errorCode: 'invalid_proof',
            },
        }
    }

    const isAggregate = Array.isArray(proof.verificationMethod)
    const methods = isAggregate ? proof.verificationMethod : [proof.verificationMethod]
    const signatureHex = proof.signatureValue
    const signature = bls.Signature.fromHex(signatureHex)

    try {
        /* ------------ CHANGED: include attributes if present ------------ */
        const payload = canonicalize(withOptionalAttributes({
            '@context': presentation['@context'],
            type: presentation['type'],
            multi_holders: presentation['multi_holders'],
            verifiableCredential: presentation['verifiableCredential'],
        }, presentation));
        /* ---------------------------------------------------------------- */

        if (!payload) throw new Error('Failed to canonicalize VC')

        const message = Uint8Array.from(Buffer.from(payload, 'utf-8'))

        // Resolve all verification methods
        const resolvedKeys = await Promise.all(
            methods.map(async (method:string) => {
                const doc = await context.agent.resolveDid({
                    didUrl: method,
                    options: resolutionOptions,
                })

                const vm = doc?.didDocument?.verificationMethod?.find((v) => {
                    if(v.type === 'Bls12381G1')
                        return v
                    else
                        return null
                })

                const hex = vm?.publicKeyHex
                if (!hex) {
                    throw new Error(`Missing public key for ${method}`)
                }
                return bls.PublicKey.fromHex(hex)
            })
        )

        const verified = isAggregate
            ? bls.verifyAggregate(resolvedKeys, message, signature)
            : bls.verify(resolvedKeys[0], message, signature)

        return verified
            ? { verified: true }
            : {
                verified: false,
                error: {
                    message: 'BLS signature verification failed',
                    errorCode: 'invalid_signature',
                },
            }
    } catch (e: any) {
        return {
            verified: false,
            error: {
                message: e.message,
                errorCode: e.code || 'verification_error',
            },
        }
    }
}


/**
 * Verify a BLS-signed Verifiable Credential
 */
export async function verifyPresentationMultiSignatureBls(
    presentation: MultiIssuerVerifiablePresentation,
    context: VerifierAgentContext,
    resolutionOptions?: DIDResolutionOptions
): Promise<IVerifyResult> {
    const proof = presentation.proof
    if (!proof || !proof.type || !proof.signatureValue) {
        return {
            verified: false,
            error: {
                message: 'Missing or malformed proof object',
                errorCode: 'invalid_proof',
            },
        }
    }

    const isAggregate = Array.isArray(proof.verificationMethod)
    if(!isAggregate){
        throw new Error('Single Signature Verification method is verifySignatureBls')
    }
    const methods = isAggregate ? proof.verificationMethod : [proof.verificationMethod]
    const signatureHex = proof.signatureValue

    try {
        /* ------------ CHANGED: include attributes if present ------------ */
        const payload = canonicalize(withOptionalAttributes({
            '@context': presentation['@context'],
            type: presentation['type'],
            multi_holders: presentation['multi_holders'],
            credentialSubject: presentation['credentialSubject'],
        }, presentation));
        /* ---------------------------------------------------------------- */

        if (!payload) throw new Error('Failed to canonicalize VC')

        const message = Uint8Array.from(Buffer.from(payload, 'utf-8'))

        const signature = bls.Signature.fromHex(signatureHex)

        // Resolve all verification methods
        const resolvedKeys = await Promise.all(
            methods.map(async (method:string) => {
                const doc = await context.agent.resolveDid({
                    didUrl: method,
                    options: resolutionOptions,
                })

                const vm = doc?.didDocument?.verificationMethod?.find((v) => {
                    if(v.type === 'Bls12381G1')
                        return v
                    else
                        return null
                })

                const hex = vm?.publicKeyHex
                if (!hex) {
                    throw new Error(`Missing public key for ${method}`)
                }
                return bls.PublicKey.fromHex(hex)
            })
        )

        //THERE IS THE POSSIBILITY OF AGGREGATING THE PUBLIC KEYS AND THEN TO verify
        //const aggregatedKeys = bls.aggregatePublicKeys(resolvedKeys)
        //const verified = bls.verify(aggregatedKeys, Buffer.from( payload,'utf-8'), signature)
        const verified = bls.verifyAggregate(resolvedKeys, Buffer.from( payload,'utf-8'),signature)

        return verified
            ? { verified: true }
            : {
                verified: false,
                error: {
                    message: 'BLS signature verification failed',
                    errorCode: 'invalid_signature',
                },
            }
    } catch (e: any) {
        return {
            verified: false,
            error: {
                message: e.message,
                errorCode: e.code || 'verification_error',
            },
        }
    }
}
