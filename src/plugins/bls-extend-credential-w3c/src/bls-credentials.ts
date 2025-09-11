//NEW ALL: LOGIC FOR BLS SIGNATURE ISSUING AND VERIFICATION

import { DIDResolutionOptions, VerifiableCredential, IVerifyResult, VerifierAgentContext } from '@veramo/core-types'
import bls  from '@chainsafe/bls'
import canonicalize from 'canonicalize'
import { hexToBytes } from '@veramo/utils'
import {MultiIssuerVerifiableCredential, ProofOfOwnershipMultiIssuerVerifiableCredential} from "./action-handler";
import {agent} from "../../../veramo/setup";
import { verifyMessage } from 'ethers';


import { ethers } from 'ethers'
import {sha256} from "@noble/hashes/sha256";
/**
 * Verify a BLS-MultiSignature Verifiable Credential then verify the proof of ownerships
 */
import {performance} from "node:perf_hooks";

export async function verifyCredentialProofOfOwnershipMultiSignatureBls(
    credential: ProofOfOwnershipMultiIssuerVerifiableCredential,
    context: VerifierAgentContext,
    resolutionOptions?: DIDResolutionOptions
): Promise<IVerifyResult & { timings?: Record<string, number> }> {

    const timings: Record<string, number> = {};
    const proof = credential.proof;

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

        const payloadToVerify = {
            '@context': credential['@context'],
            multi_issuers: credential.multi_issuers,
            credentialSubject: credential.credentialSubject,
            type: credential.type,
            aggregated_bls_public_key: credential.aggregated_bls_public_key,
        };

        const payload = canonicalize(payloadToVerify);
        if (!payload) throw new Error('Failed to canonicalize VC');
        const message = Uint8Array.from(Buffer.from(payload, 'utf-8'));

        // --- BLS Signature Verification ---
        const t1 = performance.now();
        const aggregatedPublicKey = bls.PublicKey.fromHex(credential.aggregated_bls_public_key);
        const firstVerify = bls.verify(aggregatedPublicKey, message, hexToBytes(proof.signatureValue));
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

        if (signatures.length !== credential.multi_issuers.length) {
            throw new Error('Signatures and multi_issuers arrays length mismatch');
        }

        for (let i = 0; i < credential.multi_issuers.length; i++) {
            const issuerDid = credential.multi_issuers[i];
            const expectedAddress = issuerDid.split(':').pop()?.toLowerCase();
            const signature = signatures[i];

            const recoveredAddress = ethers.verifyMessage(JSON.stringify(payload), signature).toLowerCase();

            if (recoveredAddress !== expectedAddress) {
                console.log("error is here: " + issuerDid + " recovered: " + recoveredAddress + " - expected: " + expectedAddress);
                return {
                    verified: false,
                    error: {
                        message: `Address mismatch for issuer ${issuerDid}`,
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
export async function aggregateMultiSignatureVerifiableCredentialBls(
    credential: any,
    options: {
        alg: string
        did: string
        signer: (data: Uint8Array) => Promise<string>
    },list_of_signatures: [string],
    settings?: {
        resolutionOptions?: DIDResolutionOptions & { publicKeyFormat?: string }
        fetchRemoteContexts?: boolean
    }
):Promise<any> {
    const payloadToSign = canonicalize({
        '@context': credential['@context'],
        type: credential['type'],
        multi_issuers: credential['multi_issuers'],
        credentialSubject: credential['credentialSubject'],
    })


    if (!payloadToSign) {
        throw new Error('Failed to canonicalize credential payload')
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
        verificationMethod: credential['multi_issuers'],
        signatureValue: signaturesAggregatedHex,
    }

    return {
        ...credential,
        proof
    }
}



// NEW: aggregate OF MULTI-SIGNATURE to make Multi Signature Verifiable Credential
export async function generateProofOfOwnershipMultiIssuerVerifiableCredentialBls(
    credential: any, proofs_of_ownership:any,list_of_signatures: string[],
    settings?: string[]
):Promise<any> {


    //console.log("before canocalize"+JSON.stringify(credential,null,2))
    const payLoad = canonicalize(credential)
    if (!payLoad) {
        throw new Error('Failed to canonicalize credential payload')
    }

    //console.log("after canocalize"+payLoad)

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
        verificationMethod: credential['multi_issuers'],
        ProofsOfOwnership: proofs_of_ownership,
        signatureValue: aggregatedSignature,
    }

    let issuanceDate = new Date().toISOString()
    return {
        ...credential, issuanceDate,
        proof
    }
}

// NEW: SIGNING OF MULTI-SIGNATURE CREDENTIALS
export async function signMultiSignatureVerifiableCredentialBls(
    credential: any,
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
    let payloadToSign
    if(!credential.aggregated_bls_public_key) {
        payloadToSign = canonicalize({
            '@context': credential['@context'],
            type: credential['type'],
            multi_issuers: credential['multi_issuers'],
            credentialSubject: credential['credentialSubject'],
        })
    }
    else{
        payloadToSign = canonicalize({
            '@context': credential['@context'],
            type: credential['type'],
            multi_issuers: credential['multi_issuers'],
            credentialSubject: credential['credentialSubject'],
            aggregated_bls_public_key: credential['aggregated_bls_public_key'],

        })


    }

    if (!payloadToSign) {
        throw new Error('Failed to canonicalize credential payload')
    }
    const signatureHex = await options.signer(Uint8Array.from(Buffer.from(payloadToSign, 'utf-8')))

    const signatureData = {
        payloadToSign,
        signatureHex,
    }
    //fundemental to understand what has been signed
    //console.log("payload that has been signed",payloadToSign)

    return {
        signatureData
    }
}


    /**
 * Create a BLS-signed Verifiable Credential
 */
export async function createVerifiableCredentialBls(
    credential: any,
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
    const payloadToSign = canonicalize({
        '@context': credential['@context'],
        type: credential['type'],
        issuer: credential['issuer'],
        issuanceDate: credential['issuanceDate'],
        credentialSubject: credential['credentialSubject'],
    })

    if (!payloadToSign) {
        throw new Error('Failed to canonicalize credential payload')
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
            '@context': credential['@context'],
            type: credential['type'],
            issuer: credential['issuer'],
            issuanceDate: credential['issuanceDate'],
            credentialSubject: credential['credentialSubject'],
            proof: proof, // explicitly last
        }
}


/**
 * Verify a BLS-signed Verifiable Credential
 */
export async function verifyCredentialBls(
    credential: VerifiableCredential,
    context: VerifierAgentContext,
    resolutionOptions?: DIDResolutionOptions
): Promise<IVerifyResult> {
    const proof = credential.proof
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
        // Canonicalize VC payload without proof
        const payload = canonicalize({
            '@context': credential['@context'],
            type: credential['type'],
            issuer: credential['issuer'],
            credentialSubject: credential['credentialSubject'],
        })


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
export async function verifyCredentialMultiSignatureBls(
    credential: MultiIssuerVerifiableCredential,
    context: VerifierAgentContext,
    resolutionOptions?: DIDResolutionOptions
): Promise<IVerifyResult> {
    const proof = credential.proof
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
        // Canonicalize VC payload without proof

        const payload = canonicalize({
            '@context': credential['@context'],
            type: credential['type'],
            multi_issuers: credential['multi_issuers'],
            credentialSubject: credential['credentialSubject'],
        })

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

