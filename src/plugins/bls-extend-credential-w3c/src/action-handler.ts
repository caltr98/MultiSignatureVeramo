//new: changed to use BLS signature with added CreateVerifiableCredentialBls method AND changed createVerifiableCredenthal method
//new: changed verifyCredential method to verify bls

import {
    DIDResolutionOptions,
    IAgentContext,
    IAgentPlugin,
    ICreateVerifiableCredentialArgs,
    ICreateVerifiablePresentationArgs,
    ICredentialPlugin,
    ICredentialStatusVerifier,
    IIdentifier,
    IKey,
    IKeyManager, IPluginMethodMap,
    IssuerAgentContext,
    IVerifyCredentialArgs,
    IVerifyPresentationArgs,
    IVerifyResult,
    ProofFormat,
    VerifiableCredential,
    VerifiablePresentation,
    VerifierAgentContext,
    W3CVerifiableCredential,
    W3CVerifiablePresentation,
} from '@veramo/core-types'

//EXTENDED PROOF FORMAT for BLS and for multi-signature
type ExtendedProofFormat =
    | ProofFormat
    | 'bls'
    | 'sign-bls-multi-signature'
    | 'aggregate-bls-multi-signature'
    | 'ProofOfOwnership-aggregate-bls-multi-signature'
    | 'sign-bls-multi-signature-vp'
    | 'aggregate-bls-multi-signature-vp'
    | 'ProofOfOwnership-aggregate-bls-multi-signature-vp';

import { schema } from '@veramo/core-types'

import {
    createVerifiableCredentialJwt,
    createVerifiablePresentationJwt,
    normalizeCredential,
    normalizePresentation,
    verifyCredential as verifyCredentialJWT,
    verifyPresentation as verifyPresentationJWT,
} from 'did-jwt-vc'

import { decodeJWT } from 'did-jwt'

import {
    asArray,
    bytesToHex,
    extractIssuer,
    hexToBytes,
    removeDIDParameters,
    isDefined,
    MANDATORY_CREDENTIAL_CONTEXT,
    processEntryToArray,
    intersect,
} from '@veramo/utils'
//import //debug from '//debug'
import { Resolvable } from 'did-resolver'

import canonicalizeLib from 'canonicalize'

const enum DocumentFormat {
    JWT,
    JSONLD,
    EIP712,
    BLS ,
}

const canonicalize = canonicalizeLib as unknown as (input: unknown) => string | undefined
import {
    createVerifiableCredentialBls,
    verifyCredentialBls,
    signMultiSignatureVerifiableCredentialBls,
    aggregateMultiSignatureVerifiableCredentialBls,
    verifyCredentialMultiSignatureBls,
    generateProofOfOwnershipMultiIssuerVerifiableCredentialBls,verifyCredentialProofOfOwnershipMultiSignatureBls
} from './bls-credentials.js'

import {
    createVerifiablePresentationBls,
    verifyPresentationBls,
    signMultiSignatureVerifiablePresentationBls,
    aggregateMultiSignatureVerifiablePresentationBls,
    verifyPresentationMultiSignatureBls,
    generateProofOfOwnershipMultiIssuerVerifiablePresentationBls,
    verifyPresentationProofOfOwnershipMultiSignatureBls,
} from './bls-presentations.js'

//const //debug = //debug('veramo:w3c:action-handler')

type BlsBackend = 'chainsafe' | 'noble'

function resolveBlsBackend(value: unknown): BlsBackend {
    return value === 'noble' ? 'noble' : 'chainsafe'
}

function readEnv(name: string): string | undefined {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const p: any = typeof process !== 'undefined' ? process : undefined
    return p?.env?.[name]
}

function strip0x(hex: string): string {
    return hex.startsWith('0x') ? hex.slice(2) : hex
}

let chainsafeBlsPromise: Promise<any> | undefined
async function getChainsafeBls(): Promise<any> {
    if (!chainsafeBlsPromise) {
        chainsafeBlsPromise = import('@chainsafe/bls').then((m: any) => m?.default ?? m)
    }
    return chainsafeBlsPromise
}

let nobleBlsPromise: Promise<any> | undefined
async function getNobleBls(): Promise<any> {
    if (!nobleBlsPromise) {
        nobleBlsPromise = import('@noble/curves/bls12-381').then((m: any) => m.bls12_381)
    }
    return nobleBlsPromise
}

export type MultiIssuerVerifiableCredential = Omit<VerifiableCredential, 'issuer' | 'issuanceDate'> & {
    multi_issuers: string[];
}
export type MultiIssuerVerifiablePresentation = Omit<VerifiablePresentation, 'holder' | 'issuanceDate'> & {
    multi_holders: string[];
}


export type ProofOfOwnershipMultiIssuerVerifiableCredential = Omit<VerifiableCredential, 'issuer' | 'issuanceDate'> & {
    multi_issuers: string[];
    aggregated_bls_public_key:string;
}
export type ProofOfOwnershipMultiIssuerVerifiablePresentation = Omit<VerifiablePresentation, 'holder'> & {
    multi_holders: string[];
    aggregated_bls_public_key:string;
}

/**
 * Arguments for verifying a BLS multisignature credential.
 *
 * @public
 */
export interface IVerifyMultisignatureCredentialArgs {
    credential: MultiIssuerVerifiableCredential;
    policies?: IVerifyCredentialArgs['policies'];
    resolutionOptions?: DIDResolutionOptions & { publicKeyFormat?: string };
}

/**
 * Arguments for verifying a proof-of-ownership protected BLS multisignature credential.
 *
 * @public
 */
export interface IVerifyProofOfOwnershipMultisignatureCredentialArgs {
    credential: ProofOfOwnershipMultiIssuerVerifiableCredential;
    policies?: IVerifyCredentialArgs['policies'];
    resolutionOptions?: DIDResolutionOptions & { publicKeyFormat?: string };
}

/**
 * Arguments for collecting a partial BLS signature for a multi-issuer credential.
 *
 * @public
 */
export type ISignMultiIssuerVerifiableCredentialArgs = Omit<ICreateVerifiableCredentialArgs, 'issuer' | 'issuanceDate'> & {
    issuer:string ;
}

/**
 * Arguments for aggregating issuer signatures into a multisigned credential.
 *
 * @public
 */
export interface ICreateMultiIssuerVerifiableCredentialArgs extends Omit<ICreateVerifiableCredentialArgs, 'issuer'> {
    issuer: string | { id: string };
    signatures: string[];
}

/**
 * Arguments for creating a proof-of-ownership protected multisignature credential.
 *
 * @public
 */
export type ICreateProofOfOwnershipMultiIssuerVerifiableCredentialArgs =
    Omit<ICreateVerifiableCredentialArgs, 'issuer' | 'issuanceDate'> & {
    signatures: string[];
    proofsOfOwnership: string[];
}

/**
 * Arguments for aggregating BLS public keys.
 *
 * @public
 */
export interface IAggregateBlsPublicKeysArgs {
    list_of_publicKeyHex: string[];
}

/**
 * Result returned by the BLS public key aggregation helper.
 *
 * @public
 */
export interface IAggregateBlsPublicKeysResult {
    bls_aggregated_pubkey: string;
}

/**
 * A serializable partial multisignature fragment.
 *
 * @public
 */
export interface IMultisignatureFragment {
    payloadToSign: string;
    signatureHex: string;
}

/**
 * Result returned when collecting a partial multisignature.
 *
 * @public
 */
export interface IMultisignatureSigningResult {
    signatureData: IMultisignatureFragment;
}

/**
 * Arguments for collecting a partial BLS signature for a multi-holder presentation.
 *
 * @public
 */
export interface ISignMultiHolderVerifiablePresentationArgs extends ICreateVerifiablePresentationArgs {
    holder: string;
}

/**
 * Arguments for aggregating holder signatures into a multisigned presentation.
 *
 * @public
 */
export interface ICreateMultiHolderVerifiablePresentationArgs extends ICreateVerifiablePresentationArgs {
    signatures: string[];
}

/**
 * Arguments for creating a proof-of-ownership protected multisignature presentation.
 *
 * @public
 */
export interface ICreateProofOfOwnershipMultiHolderVerifiablePresentationArgs extends ICreateVerifiablePresentationArgs {
    signatures: string[];
    proofsOfOwnership: string[];
}

/**
 * Arguments for verifying a BLS multisignature presentation.
 *
 * @public
 */
export interface IVerifyMultisignaturePresentationArgs {
    presentation: MultiIssuerVerifiablePresentation;
    resolutionOptions?: DIDResolutionOptions & { publicKeyFormat?: string };
}

/**
 * Arguments for verifying a proof-of-ownership protected BLS multisignature presentation.
 *
 * @public
 */
export interface IVerifyProofOfOwnershipMultisignaturePresentationArgs {
    presentation: ProofOfOwnershipMultiIssuerVerifiablePresentation;
    resolutionOptions?: DIDResolutionOptions & { publicKeyFormat?: string };
}


export interface ICustomCredentialPlugin extends IPluginMethodMap {
    // VC (multi-issuer)
    signMultiIssuedVerifiableCredential(
        args: ISignMultiIssuerVerifiableCredentialArgs,
        context: IssuerAgentContext
    ): Promise<IMultisignatureSigningResult>;

    aggregateBlsPublicKeys(
        args: IAggregateBlsPublicKeysArgs,
        context: IssuerAgentContext
    ): Promise<IAggregateBlsPublicKeysResult>;

    createMultiIssuerVerifiableCredential(
        args: ICreateMultiIssuerVerifiableCredentialArgs,
        context: IssuerAgentContext
    ): Promise<VerifiableCredential>;

    createProofOfOwnershipMultiIssuerVerifiableCredential(
        args: ICreateProofOfOwnershipMultiIssuerVerifiableCredentialArgs,
        context: IssuerAgentContext
    ): Promise<VerifiableCredential>;

    verifyMultisignatureCredential(
        args: IVerifyMultisignatureCredentialArgs,
        context: VerifierAgentContext
    ): Promise<IVerifyResult>;

    verifyProofOfOwnershipMultisignatureCredential(
        args: IVerifyProofOfOwnershipMultisignatureCredentialArgs,
        context: VerifierAgentContext
    ): Promise<IVerifyResult>;

    signMultiHolderVerifiablePresentation(
        args: ISignMultiHolderVerifiablePresentationArgs,
        context: IssuerAgentContext
    ): Promise<IMultisignatureSigningResult>;

    createMultiHolderVerifiablePresentation(
        args: ICreateMultiHolderVerifiablePresentationArgs,
        context: IssuerAgentContext
    ): Promise<VerifiablePresentation>;

    createProofOfOwnershipMultiHolderVerifiablePresentation(
        args: ICreateProofOfOwnershipMultiHolderVerifiablePresentationArgs,
        context: IssuerAgentContext
    ): Promise<VerifiablePresentation>;

    verifyMultisignaturePresentation(
        args: IVerifyMultisignaturePresentationArgs,
        context: VerifierAgentContext
    ): Promise<IVerifyResult>;

    verifyProofOfOwnershipMultisignaturePresentation(
        args: IVerifyProofOfOwnershipMultisignaturePresentationArgs,
        context: VerifierAgentContext
    ): Promise<IVerifyResult>;
}


/**
 * A Veramo plugin that implements the {@link @veramo/core-types#ICredentialPlugin | ICredentialPlugin} methods.
 *
 * @public
 */
export class CredentialPlugin implements IAgentPlugin {
    readonly methods: ICredentialPlugin & ICustomCredentialPlugin
    private readonly blsBackend: BlsBackend
    readonly schema = {
        components: {
            schemas: {
                ...schema.ICredentialIssuer.components.schemas,
                ...schema.ICredentialVerifier.components.schemas,
            },
            methods: {
                ...schema.ICredentialIssuer.components.methods,
                ...schema.ICredentialVerifier.components.methods,

                signMultiIssuedVerifiableCredential: {
                    description: 'Signs a credential with BLS or other proof format in a multi-issuer scenario',
                    arguments: {
                        type: 'object',
                        properties: {
                            credential: { type: 'object' },
                            proofFormat: { type: 'string' },
                            keyRef: { type: 'string' },
                            save: { type: 'boolean' },
                            now: { type: 'number' },
                        },
                        required: ['credential'],
                    },
                    returns: {
                        type: 'object',
                        properties: {
                            signatureData: {
                                type: 'object',
                                properties: {
                                    payloadToSign: { type: 'string' },
                                    signatureHex: { type: 'string' },
                                },
                                required: ['payloadToSign', 'signatureHex'],
                            },
                        },
                        required: ['signatureData'],
                    },
                },
                aggregateBlsPublicKeys: {
                    description: 'Aggregates multiple BLS public keys into one public key',
                    arguments: {
                        type: 'object',
                        properties: {
                            list_of_publicKeyHex: { type: 'array', items: { type: 'string' } },
                        },
                        required: ['list_of_publicKeyHex'],
                    },
                    returns: {
                        type: 'object',
                        properties: {
                            bls_aggregated_pubkey: { type: 'string' },
                        },
                        required: ['bls_aggregated_pubkey'],
                    },
                },
                createMultiIssuerVerifiableCredential: {
                    description: 'Aggregates BLS signatures from multiple issuers and produces a final Verifiable Credential',
                    arguments: {
                        type: 'object',
                        properties: {
                            credential: { type: 'object' },
                            proofFormat: { type: 'string' },
                            issuer: {
                                oneOf: [
                                    { type: 'string' },
                                    {
                                        type: 'object',
                                        properties: { id: { type: 'string' } },
                                        required: ['id'],
                                    },
                                ],
                            },
                            keyRef: { type: 'string' },
                            signatures: { type: 'array', items: { type: 'string' } },
                            save: { type: 'boolean' },
                            now: { type: 'number' },
                        },
                        required: ['credential', 'proofFormat', 'issuer', 'signatures'],
                    },
                    returns: {
                        type: 'object',
                    },
                },
                createProofOfOwnershipMultiIssuerVerifiableCredential: {
                    description: 'Creates a proof-of-ownership protected multisignature credential',
                    arguments: {
                        type: 'object',
                        properties: {
                            credential: { type: 'object' },
                            proofFormat: { type: 'string' },
                            signatures: { type: 'array', items: { type: 'string' } },
                            proofsOfOwnership: { type: 'array', items: { type: 'string' } },
                        },
                        required: ['credential', 'proofFormat', 'signatures', 'proofsOfOwnership'],
                    },
                    returns: {
                        type: 'object',
                    },
                },
                verifyMultisignatureCredential: {
                    description: 'Verifies a multi-signature BLS credential without issuer, using multi_issuers[] instead',
                    arguments: {
                        type: 'object',
                        properties: {
                            credential: { type: 'object' },
                            policies: { type: 'object' },
                            resolutionOptions: { type: 'object' },
                        },
                        required: ['credential'],
                    },
                    returns: {
                        type: 'object',
                    },
                },
                verifyProofOfOwnershipMultisignatureCredential: {
                    description: 'Verifies a proof-of-ownership protected multisignature credential',
                    arguments: {
                        type: 'object',
                        properties: {
                            credential: { type: 'object' },
                            policies: { type: 'object' },
                            resolutionOptions: { type: 'object' },
                        },
                        required: ['credential'],
                    },
                    returns: {
                        type: 'object',
                    },
                },
                signMultiHolderVerifiablePresentation: {
                    description: 'Collect a BLS partial signature for a multi-holder VP',
                    arguments: { type: 'object', properties: { presentation: {type:'object'}, holder:{type:'string'}, keyRef:{type:'string'} }, required: ['presentation','holder'] },
                    returns: {
                        type: 'object',
                        properties: {
                            signatureData: {
                                type: 'object',
                                properties: {
                                    payloadToSign: { type: 'string' },
                                    signatureHex: { type: 'string' },
                                },
                                required: ['payloadToSign', 'signatureHex'],
                            },
                        },
                        required: ['signatureData'],
                    },
                },
                createMultiHolderVerifiablePresentation: {
                    description: 'Aggregate BLS partial signatures into a multi-holder VP',
                    arguments: { type:'object', properties:{ presentation:{type:'object'}, signatures:{type:'array', items:{type:'string'}}, keyRef:{type:'string'} }, required:['presentation','signatures'] },
                    returns: { type:'object' },
                },
                createProofOfOwnershipMultiHolderVerifiablePresentation: {
                    description: 'Attach PoO & aggregated BLS sig to VP (multi-holder)',
                    arguments: { type:'object', properties:{ presentation:{type:'object'}, signatures:{type:'array',items:{type:'string'}}, proofsOfOwnership:{type:'array',items:{type:'string'}} }, required:['presentation','signatures','proofsOfOwnership'] },
                    returns: { type:'object' },
                },
                verifyMultisignaturePresentation: {
                    description: 'Verify multi-holder VP aggregated BLS signature',
                    arguments: { type:'object', properties:{ presentation:{type:'object'}, resolutionOptions:{type:'object'} }, required:['presentation'] },
                    returns: { type:'object' },
                },
                verifyProofOfOwnershipMultisignaturePresentation: {
                    description: 'Verify multi-holder VP PoO + aggregated BLS signature',
                    arguments: { type:'object', properties:{ presentation:{type:'object'}, resolutionOptions:{type:'object'} }, required:['presentation'] },
                    returns: { type:'object' },
                }
            },
        },
    }

    constructor(options?: { blsBackend?: BlsBackend } & Record<string, any>) {
        this.blsBackend = options?.blsBackend ?? resolveBlsBackend(readEnv('VERAMO_BLS_BACKEND'))
        this.methods = {
            createVerifiablePresentation: this.createVerifiablePresentation.bind(this),
            createVerifiableCredential: this.createVerifiableCredential.bind(this),
            verifyCredential: this.verifyCredential.bind(this),
            verifyPresentation: this.verifyPresentation.bind(this),
            matchKeyForJWT: this.matchKeyForJWT.bind(this),
            listUsableProofFormats: this.listUsableProofFormats.bind(this),

            // Added custom NEW function
            signMultiIssuedVerifiableCredential: this.signMultiIssuedVerifiableCredential.bind(this),
            createMultiIssuerVerifiableCredential: this.createMultiIssuerVerifiableCredential.bind(this),
            verifyMultisignatureCredential: this.verifyMultisignatureCredential.bind(this),
            aggregateBlsPublicKeys: this.aggregateBlsPublicKeys.bind(this),
            createProofOfOwnershipMultiIssuerVerifiableCredential: this.createProofOfOwnershipMultiIssuerVerifiableCredential.bind(this),
            verifyProofOfOwnershipMultisignatureCredential: this.verifyProofOfOwnershipMultisignatureCredential.bind(this),

            // VP helpers mirroring VC modus operandi
            signMultiHolderVerifiablePresentation: this.signMultiHolderVerifiablePresentation.bind(this),
            createMultiHolderVerifiablePresentation: this.createMultiHolderVerifiablePresentation.bind(this),
            createProofOfOwnershipMultiHolderVerifiablePresentation:
                this.createProofOfOwnershipMultiHolderVerifiablePresentation.bind(this),
            verifyMultisignaturePresentation: this.verifyMultisignaturePresentation.bind(this),
            verifyProofOfOwnershipMultisignaturePresentation:
                this.verifyProofOfOwnershipMultisignaturePresentation.bind(this),

        }
    }

    /**
     * Verifies a multisignature credential using the issuer list embedded in the document.
     *
     * @public
     */
    async verifyMultisignatureCredential(args: IVerifyMultisignatureCredentialArgs, context: VerifierAgentContext): Promise<IVerifyResult> {
        let { credential, policies, ...otherOptions } = args
        let verificationResult: IVerifyResult = { verified: false }


        const type: DocumentFormat = 3
        if (type === 3) {
            try {
                verificationResult = await verifyCredentialMultiSignatureBls(
                    credential ,
                    context,
                    otherOptions?.resolutionOptions,
                    this.blsBackend,
                )
                return verificationResult;
            } catch (e: any) {
                return {
                    verified: false,
                    error: {
                        message: e.message,
                        errorCode: e.code || 'bls_verification_error',
                    },
                }
            }
        }
        return verificationResult
    }
    /**
     * Verifies a proof-of-ownership protected multisignature credential.
     *
     * @public
     */
    async verifyProofOfOwnershipMultisignatureCredential(args: IVerifyProofOfOwnershipMultisignatureCredentialArgs, context: VerifierAgentContext): Promise<IVerifyResult> {
        let { credential, policies, ...otherOptions } = args
        let verificationResult: IVerifyResult = { verified: false }


        const type: DocumentFormat = 3
        if (type === 3) {
            try {
                verificationResult = await verifyCredentialProofOfOwnershipMultiSignatureBls(
                    credential as ProofOfOwnershipMultiIssuerVerifiableCredential ,
                    context,
                    otherOptions?.resolutionOptions,
                    this.blsBackend,
                )
                return verificationResult;
            } catch (e: any) {
                return {
                    verified: false,
                    error: {
                        message: e.message,
                        errorCode: e.code || 'bls_verification_error',
                    },
                }
            }
        }
        return verificationResult
    }

    /** {@inheritdoc @veramo/core-types#ICredentialIssuer.createVerifiablePresentation} */
    async createVerifiablePresentation(
        args: ICreateVerifiablePresentationArgs,
        context: IssuerAgentContext,
    ): Promise<VerifiablePresentation> {
        let {
            presentation,
            proofFormat,
            domain,
            challenge,
            removeOriginalFields,
            keyRef,
            save,
            now,
            ...otherOptions
        } = args
        const presentationContext: string[] = processEntryToArray(
            args?.presentation?.['@context'],
            MANDATORY_CREDENTIAL_CONTEXT,
        )
        const presentationType = processEntryToArray(args?.presentation?.type, 'VerifiablePresentation')
        presentation = {
            ...presentation,
            '@context': presentationContext,
            type: presentationType,
        }

        if (!isDefined(presentation.holder)) {
            throw new Error('invalid_argument: presentation.holder must not be empty')
        }

        if (presentation.verifiableCredential) {
            presentation.verifiableCredential = presentation.verifiableCredential.map((cred) => {
                // map JWT credentials to their canonical form
                if (typeof cred !== 'string' && cred.proof.jwt) {
                    return cred.proof.jwt
                } else {
                    return cred
                }
            })
        }

        const holder = removeDIDParameters(presentation.holder)

        let identifier: IIdentifier
        try {
            identifier = await context.agent.didManagerGet({ did: holder })
        } catch (e) {
            throw new Error('invalid_argument: presentation.holder must be a DID managed by this agent')
        }
        const key = pickSigningKey(identifier, keyRef)

        let verifiablePresentation: VerifiablePresentation

        if (proofFormat === 'lds') {
            if (typeof context.agent.createVerifiablePresentationLD === 'function') {
                verifiablePresentation = await context.agent.createVerifiablePresentationLD({ ...args, presentation })
            } else {
                throw new Error(
                    'invalid_setup: your agent does not seem to have ICredentialIssuerLD plugin installed',
                )
            }
        } else if (proofFormat === 'EthereumEip712Signature2021') {
            if (typeof context.agent.createVerifiablePresentationEIP712 === 'function') {
                verifiablePresentation = await context.agent.createVerifiablePresentationEIP712({
                    ...args,
                    presentation,
                })
            } else {
                throw new Error(
                    'invalid_setup: your agent does not seem to have ICredentialIssuerEIP712 plugin installed',
                )
            }
        } else {
            // only add issuanceDate for JWT
            now = typeof now === 'number' ? new Date(now * 1000) : now
            if (!Object.getOwnPropertyNames(presentation).includes('issuanceDate')) {
                presentation.issuanceDate = (now instanceof Date ? now : new Date()).toISOString()
            }

            //debug('Signing VP with', identifier.did)
            let alg = 'ES256K'
            if (key.type === 'Ed25519') {
                alg = 'EdDSA'
            } else if (key.type === 'Secp256r1') {
                alg = 'ES256'
            }

            const signer = wrapSigner(context, key, alg)
            const jwt = await createVerifiablePresentationJwt(
                presentation as any,
                { did: identifier.did, signer, alg },
                { removeOriginalFields, challenge, domain, ...otherOptions },
            )
            //FIXME: flagging this as a potential privacy leak.
            //debug(jwt)
            verifiablePresentation = normalizePresentation(jwt)
        }
        if (save) {
            await context.agent.dataStoreSaveVerifiablePresentation({ verifiablePresentation })
        }
        return verifiablePresentation
    }

    /**
     * Aggregates multiple BLS public keys into a single public key.
     *
     * @public
     */
    async aggregateBlsPublicKeys(
        args: IAggregateBlsPublicKeysArgs,
        context: IssuerAgentContext
    ): Promise<IAggregateBlsPublicKeysResult> {
        if (this.blsBackend === 'noble') {
            const bls = await getNobleBls()
            const publicKeys = args.list_of_publicKeyHex.map((hex) => hexToBytes(strip0x(hex.trim())))
            const aggregatedKey: Uint8Array = bls.aggregatePublicKeys(publicKeys)
            return { bls_aggregated_pubkey: bytesToHex(aggregatedKey) }
        } else {
            const bls = await getChainsafeBls()
            const publicKeys = args.list_of_publicKeyHex.map((hex) =>
                bls.PublicKey.fromBytes(Buffer.from(hex.trim(), 'hex')),
            )
            const aggregatedKey: Uint8Array = bls.aggregatePublicKeys(publicKeys)
            return { bls_aggregated_pubkey: bytesToHex(aggregatedKey) }
        }
    }
    /**
     * Collects a partial BLS signature for a multi-issuer credential payload.
     *
     * @public
     */
    async signMultiIssuedVerifiableCredential(
        args: ISignMultiIssuerVerifiableCredentialArgs,
        context: IssuerAgentContext,
    ): Promise<IMultisignatureSigningResult> {
        let { credential,issuer, proofFormat, keyRef, removeOriginalFields, save, now, ...otherOptions } = args
        const credentialContext = processEntryToArray(credential['@context'], MANDATORY_CREDENTIAL_CONTEXT)
        const credentialType = processEntryToArray(credential.type, 'VerifiableCredential')

        credential = {
            ...credential,
            '@context': credentialContext,
            type: credentialType,
        }

        //FIXME: if the identifier is not found, the error message should reflect that.
         //issuer = extractIssuer({credential:{issuer:issuer}} as VerifiableCredential, { removeParameters: true })
        if (!issuer || typeof issuer === 'undefined') {
            throw new Error('invalid_argument: credential.issuer must not be empty')
        }

        let identifier: IIdentifier
        try {
            identifier = await context.agent.didManagerGet({ did: issuer })
        } catch (e) {
            throw new Error(`invalid_argument: credential.issuer must be a DID managed by this agent. ${e}`)
        }
        try {
            let signingResult: IMultisignatureSigningResult

            if (
                (proofFormat as ExtendedProofFormat) === 'sign-bls-multi-signature' ||
                (proofFormat as ExtendedProofFormat) === 'sign-bls-multi-signature-vp' ||
                (proofFormat as ExtendedProofFormat) === 'aggregate-bls-multi-signature-vp' ||
                (proofFormat as ExtendedProofFormat) === 'ProofOfOwnership-aggregate-bls-multi-signature-vp'
            ){
                const key = pickSigningKey(identifier, keyRef)


                //console.log("key got from pick"+JSON.stringify(key,null,2))
                //debug('Signing VC with', identifier.did)
                let alg = 'BLS_SIGNATURE'

                const signer = wrapSigner(context, key, alg)
                const signature_data = await signMultiSignatureVerifiableCredentialBls(
                    credential as any,
                    { did: identifier.did, signer, alg },
                    { ...otherOptions },
                )
                signingResult = signature_data
                return signingResult;
            }
            else {
                throw new Error('invalid_argument: proofFormat must be "sign-bls-multi-signature" or any other supported proof format')
            }
            return signingResult;
        } catch (error) {
            //debug(error)
            return Promise.reject(error)
        }
    }


    /**
     * Aggregates multiple issuer signatures into a final multisignature credential.
     *
     * @public
     */
    async createMultiIssuerVerifiableCredential(
        args: ICreateMultiIssuerVerifiableCredentialArgs,
        context: IssuerAgentContext,
    ): Promise<VerifiableCredential> {
        let { credential,issuer, proofFormat, keyRef,signatures, removeOriginalFields, save, now, ...otherOptions } = args
        const credentialContext = processEntryToArray(credential['@context'], MANDATORY_CREDENTIAL_CONTEXT)
        const credentialType = processEntryToArray(credential.type, 'VerifiableCredential')

        credential = {
            ...credential,
            '@context': credentialContext,
            type: credentialType,
        }
        const issuerDid = typeof issuer === 'string' ? issuer : issuer?.id

        if (!issuerDid || typeof issuerDid === 'undefined') {
            throw new Error('invalid_argument: credential.issuer must not be empty')
        }

        let identifier: IIdentifier
        try {
            identifier = await context.agent.didManagerGet({ did: issuerDid })
        } catch (e) {
            throw new Error(`invalid_argument: credential.issuer must be a DID managed by this agent. ${e}`)
        }
        try {
            let signedVerifiableCredential: VerifiableCredential

            if (proofFormat as ExtendedProofFormat === 'aggregate-bls-multi-signature'){
                const key = pickSigningKey(identifier, keyRef)

                //debug('Signing VC with', identifier.did)
                let alg = 'BLS_AGGREGATE_MULTI_SIGNATURE'

                const signer = wrapSigner(context, key, alg)
                const jwt = await aggregateMultiSignatureVerifiableCredentialBls(
                    credential as any,
                    { did: identifier.did, signer, alg },signatures,
                    { ...otherOptions },
                )
                //debug(jwt)
                signedVerifiableCredential = normalizeCredential(jwt)
                return signedVerifiableCredential;
            }
            else {
                throw new Error('invalid_argument: proofFormat must be "bls-multi-signature" or any other supported proof format')
            }
            return signedVerifiableCredential;
        } catch (error) {
            //debug(error)
            return Promise.reject(error)
        }
    }
    /**
     * Creates a proof-of-ownership protected multisignature credential.
     *
     * @public
     */
    async createProofOfOwnershipMultiIssuerVerifiableCredential(
        args: ICreateProofOfOwnershipMultiIssuerVerifiableCredentialArgs,
        context: IssuerAgentContext,
    ): Promise<VerifiableCredential> {
        let { credential,proofData,type, proofsOfOwnership, proofFormat,signatures, removeOriginalFields, save, now, ...otherOptions } = args
        const credentialContext = processEntryToArray(credential['@context'], MANDATORY_CREDENTIAL_CONTEXT)
        const credentialType = processEntryToArray(credential.type, 'VerifiableCredential')

        credential = {
            ...credential,
            '@context': credentialContext,
            type: credentialType,
        }

        try {
            let signedVerifiableCredential: VerifiableCredential
            if (proofFormat as ExtendedProofFormat === 'ProofOfOwnership-aggregate-bls-multi-signature'){
                signedVerifiableCredential = await generateProofOfOwnershipMultiIssuerVerifiableCredentialBls(
                    credential,
                    proofsOfOwnership,
                    signatures,
                    undefined,
                    this.blsBackend,
                )


                return signedVerifiableCredential;
            }
            else {
                throw new Error('invalid_argument: proofFormat must be "bls-multi-signature" or any other supported proof format')
            }


            return signedVerifiableCredential;
        } catch (error) {
            //debug(error)
            return Promise.reject(error)
        }
    }



    /** {@inheritdoc @veramo/core-types#ICredentialIssuer.createVerifiableCredential} */
    async createVerifiableCredential(
        args: ICreateVerifiableCredentialArgs,
        context: IssuerAgentContext,
    ): Promise<VerifiableCredential> {
        let { credential, proofFormat, keyRef, removeOriginalFields, save, now, ...otherOptions } = args
        const credentialContext = processEntryToArray(credential['@context'], MANDATORY_CREDENTIAL_CONTEXT)
        const credentialType = processEntryToArray(credential.type, 'VerifiableCredential')

        // only add issuanceDate for JWT
        now = typeof now === 'number' ? new Date(now * 1000) : now
        if (!Object.getOwnPropertyNames(credential).includes('issuanceDate')) {
            credential.issuanceDate = (now instanceof Date ? now : new Date()).toISOString()
        }

        credential = {
            ...credential,
            '@context': credentialContext,
            type: credentialType,
        }

        //FIXME: if the identifier is not found, the error message should reflect that.
        const issuer = extractIssuer(credential, { removeParameters: true })
        if (!issuer || typeof issuer === 'undefined') {
            throw new Error('invalid_argument: credential.issuer must not be empty')
        }

        let identifier: IIdentifier
        try {
            identifier = await context.agent.didManagerGet({ did: issuer })
        } catch (e) {
            throw new Error(`invalid_argument: credential.issuer must be a DID managed by this agent. ${e}`)
        }
        try {
            let verifiableCredential: VerifiableCredential

            if (proofFormat as ExtendedProofFormat === 'bls'){
                const key = pickSigningKey(identifier, keyRef)

                //debug('Signing VC with', identifier.did)
                let alg = 'BLS_SIGNATURE'

                const signer = wrapSigner(context, key, alg)
                const jwt = await createVerifiableCredentialBls(
                    credential as any,
                    { did: identifier.did, signer, alg },
                    { ...otherOptions },
                )
                //FIXME: flagging this as a potential privacy leak.
                //debug(jwt)
                verifiableCredential = normalizeCredential(jwt)

                return verifiableCredential;
            }
            if (proofFormat === 'lds') {
                if (typeof context.agent.createVerifiableCredentialLD === 'function') {
                    verifiableCredential = await context.agent.createVerifiableCredentialLD({ ...args, credential })
                } else {
                    throw new Error(
                        'invalid_setup: your agent does not seem to have ICredentialIssuerLD plugin installed',
                    )
                }
            } else if (proofFormat === 'EthereumEip712Signature2021') {
                if (typeof context.agent.createVerifiableCredentialEIP712 === 'function') {
                    verifiableCredential = await context.agent.createVerifiableCredentialEIP712({ ...args, credential })
                } else {
                    throw new Error(
                        'invalid_setup: your agent does not seem to have ICredentialIssuerEIP712 plugin installed',
                    )
                }
            } else {
                const key = pickSigningKey(identifier, keyRef)

                //debug('Signing VC with', identifier.did)
                let alg = 'ES256K'
                if (key.type === 'Ed25519') {
                    alg = 'EdDSA'
                } else if (key.type === 'Secp256r1') {
                    alg = 'ES256'
                }

                const signer = wrapSigner(context, key, alg)
                const jwt = await createVerifiableCredentialJwt(
                    credential as any,
                    { did: identifier.did, signer, alg },
                    { removeOriginalFields, ...otherOptions },
                )
                //FIXME: flagging this as a potential privacy leak.
                //debug(jwt)
                verifiableCredential = normalizeCredential(jwt)
            }
            if (save) {
                await context.agent.dataStoreSaveVerifiableCredential({ verifiableCredential })
            }

            return verifiableCredential
        } catch (error) {
            //debug(error)
            return Promise.reject(error)
        }
    }

    /** {@inheritdoc @veramo/core-types#ICredentialVerifier.verifyCredential} */
    async verifyCredential(args: IVerifyCredentialArgs, context: VerifierAgentContext): Promise<IVerifyResult> {
        let { credential, policies, ...otherOptions } = args
        let verifiedCredential: VerifiableCredential
        let verificationResult: IVerifyResult = { verified: false }

        const type: DocumentFormat = detectDocumentType(credential)
        if (type === DocumentFormat.BLS) {
            try {
                verificationResult = await verifyCredentialBls(
                    credential as VerifiableCredential,
                    context,
                    otherOptions?.resolutionOptions,
                    this.blsBackend,
                )
                return verificationResult;
            } catch (e: any) {
                return {
                    verified: false,
                    error: {
                        message: e.message,
                        errorCode: e.code || 'bls_verification_error',
                    },
                }
            }
        }
        if (type == DocumentFormat.JWT) {
            let jwt: string = typeof credential === 'string' ? credential : credential.proof.jwt

            const resolver = {
                resolve: (didUrl: string) =>
                    context.agent.resolveDid({
                        didUrl,
                        options: otherOptions?.resolutionOptions,
                    }),
            } as Resolvable
            try {
                // needs broader credential as well to check equivalence with jwt
                verificationResult = await verifyCredentialJWT(jwt, resolver, {
                    ...otherOptions,
                    policies: {
                        ...policies,
                        nbf: policies?.nbf ?? policies?.issuanceDate,
                        iat: policies?.iat ?? policies?.issuanceDate,
                        exp: policies?.exp ?? policies?.expirationDate,
                        aud: policies?.aud ?? policies?.audience,
                    },
                })
                verifiedCredential = verificationResult.verifiableCredential

                // if credential was presented with other fields, make sure those fields match what's in the JWT
                if (typeof credential !== 'string' && credential.proof.type === 'JwtProof2020') {
                    const credentialCopy = JSON.parse(JSON.stringify(credential))
                    delete credentialCopy.proof.jwt

                    const verifiedCopy = JSON.parse(JSON.stringify(verifiedCredential))
                    delete verifiedCopy.proof.jwt

                    if (canonicalize(credentialCopy) !== canonicalize(verifiedCopy)) {
                        verificationResult.verified = false
                        verificationResult.error = new Error(
                            'invalid_credential: Credential JSON does not match JWT payload',
                        )
                    }
                }
            } catch (e: any) {
                let { message, errorCode } = e
                return {
                    verified: false,
                    error: {
                        message,
                        errorCode: errorCode ? errorCode : message.split(':')[0],
                    },
                }
            }
        } else if (type == DocumentFormat.EIP712) {
            if (typeof context.agent.verifyCredentialEIP712 !== 'function') {
                throw new Error(
                    'invalid_setup: your agent does not seem to have ICredentialIssuerEIP712 plugin installed',
                )
            }

            try {
                const result = await context.agent.verifyCredentialEIP712(args)
                if (result) {
                    verificationResult = {
                        verified: true,
                    }
                } else {
                    verificationResult = {
                        verified: false,
                        error: {
                            message: 'invalid_signature: The signature does not match any of the issuer signing keys',
                            errorCode: 'invalid_signature',
                        },
                    }
                }
                verifiedCredential = <VerifiableCredential>credential
            } catch (e: any) {
                //debug('encountered error while verifying EIP712 credential: %o', e)
                const { message, errorCode } = e
                return {
                    verified: false,
                    error: {
                        message,
                        errorCode: errorCode ? errorCode : e.message.split(':')[0],
                    },
                }
            }
        } else if (type == DocumentFormat.JSONLD) {
            if (typeof context.agent.verifyCredentialLD !== 'function') {
                throw new Error(
                    'invalid_setup: your agent does not seem to have ICredentialIssuerLD plugin installed',
                )
            }

            verificationResult = await context.agent.verifyCredentialLD({ ...args, now: policies?.now })
            verifiedCredential = <VerifiableCredential>credential
        } else {
            throw new Error('invalid_argument: Unknown credential type.')
        }

        if (policies?.credentialStatus !== false && (await isRevoked(verifiedCredential, context as any))) {
            verificationResult = {
                verified: false,
                error: {
                    message: 'revoked: The credential was revoked by the issuer',
                    errorCode: 'revoked',
                },
            }
        }

        return verificationResult
    }


    /** {@inheritdoc @veramo/core-types#ICredentialVerifier.verifyPresentation} */
    async verifyPresentation(
        args: IVerifyPresentationArgs,
        context: VerifierAgentContext,
    ): Promise<IVerifyResult> {
        let { presentation, domain, challenge, fetchRemoteContexts, policies, ...otherOptions } = args
        const type: DocumentFormat = detectDocumentType(presentation)
        if (type === DocumentFormat.JWT) {
            // JWT
            let jwt: string
            if (typeof presentation === 'string') {
                jwt = presentation
            } else {
                jwt = presentation.proof.jwt
            }
            const resolver = {
                resolve: (didUrl: string) =>
                    context.agent.resolveDid({
                        didUrl,
                        options: otherOptions?.resolutionOptions,
                    }),
            } as Resolvable

            let audience = domain
            if (!audience) {
                const { payload } = await decodeJWT(jwt)
                if (payload.aud) {
                    // automatically add a managed DID as audience if one is found
                    const intendedAudience = asArray(payload.aud)
                    const managedDids = await context.agent.didManagerFind()
                    const filtered = managedDids.filter((identifier) => intendedAudience.includes(identifier.did))
                    if (filtered.length > 0) {
                        audience = filtered[0].did
                    }
                }
            }

            try {
                return await verifyPresentationJWT(jwt, resolver, {
                    challenge,
                    domain,
                    audience,
                    policies: {
                        ...policies,
                        nbf: policies?.nbf ?? policies?.issuanceDate,
                        iat: policies?.iat ?? policies?.issuanceDate,
                        exp: policies?.exp ?? policies?.expirationDate,
                        aud: policies?.aud ?? policies?.audience,
                    },
                    ...otherOptions,
                })
            } catch (e: any) {
                let { message, errorCode } = e
                return {
                    verified: false,
                    error: {
                        message,
                        errorCode: errorCode ? errorCode : message.split(':')[0],
                    },
                }
            }
        } else if (type === DocumentFormat.EIP712) {
            // JSON-LD
            if (typeof context.agent.verifyPresentationEIP712 !== 'function') {
                throw new Error(
                    'invalid_setup: your agent does not seem to have ICredentialIssuerEIP712 plugin installed',
                )
            }
            try {
                const result = await context.agent.verifyPresentationEIP712(args)
                if (result) {
                    return {
                        verified: true,
                    }
                } else {
                    return {
                        verified: false,
                        error: {
                            message: 'invalid_signature: The signature does not match any of the issuer signing keys',
                            errorCode: 'invalid_signature',
                        },
                    }
                }
            } catch (e: any) {
                const { message, errorCode } = e
                return {
                    verified: false,
                    error: {
                        message,
                        errorCode: errorCode ? errorCode : e.message.split(':')[0],
                    },
                }
            }
        } else {
            // JSON-LD
            if (typeof context.agent.verifyPresentationLD === 'function') {
                const result = await context.agent.verifyPresentationLD({ ...args, now: policies?.now })
                return result
            } else {
                throw new Error(
                    'invalid_setup: your agent does not seem to have ICredentialIssuerLD plugin installed',
                )
            }
        }
    }

    /**
     * Checks if a key is suitable for signing JWT payloads.
     * @param key - the key to check
     * @param context - the Veramo agent context, unused here
     *
     * @beta
     */
    async matchKeyForJWT(key: IKey, context: IssuerAgentContext): Promise<boolean> {
        switch (key.type) {
            case 'Ed25519':
            case 'Secp256r1':
                return true
            case 'Secp256k1':
                return intersect(key.meta?.algorithms ?? [], ['ES256K', 'ES256K-R']).length > 0
            default:
                return false
        }
        return false
    }

    async listUsableProofFormats(did: IIdentifier, context: IssuerAgentContext): Promise<ProofFormat[]> {
        const signingOptions: ProofFormat[] = []
        const keys = did.keys
        for (const key of keys) {
            if (context.agent.availableMethods().includes('matchKeyForJWT')) {
                if (await context.agent.matchKeyForJWT(key)) {
                    signingOptions.push('jwt')
                }
            }
            if (context.agent.availableMethods().includes('matchKeyForLDSuite')) {
                if (await context.agent.matchKeyForLDSuite(key)) {
                    signingOptions.push('lds')
                }
            }
            if (context.agent.availableMethods().includes('matchKeyForEIP712')) {
                if (await context.agent.matchKeyForEIP712(key)) {
                    signingOptions.push('EthereumEip712Signature2021')
                }
            }
        }
        return signingOptions
    }
    /**
     * Collects a partial BLS signature for a multi-holder presentation payload.
     *
     * @public
     */
    async signMultiHolderVerifiablePresentation(
        args: ISignMultiHolderVerifiablePresentationArgs,
        context: IssuerAgentContext,
    ): Promise<IMultisignatureSigningResult> {
        const { presentation, holder, keyRef, ...otherOptions } = args
        const presCtx = processEntryToArray(presentation['@context'], MANDATORY_CREDENTIAL_CONTEXT)
        const presType = processEntryToArray(presentation.type, 'VerifiablePresentation')
        const normalized = { ...presentation, '@context': presCtx, type: presType }

        const identifier = await context.agent.didManagerGet({ did: holder })
        const key = pickSigningKey(identifier, keyRef)
        const alg = 'BLS_SIGNATURE'
        const signer = wrapSigner(context, key, alg)

        // returns { signatureData: { payloadToSign, signatureHex } }
        return await signMultiSignatureVerifiablePresentationBls(
            normalized as any,
            { did: identifier.did, signer, alg },
            { ...otherOptions },
        )
    }

    /**
     * Aggregates holder signatures into a final multisignature presentation.
     *
     * @public
     */
    async createMultiHolderVerifiablePresentation(
        args: ICreateMultiHolderVerifiablePresentationArgs,
        context: IssuerAgentContext,
    ): Promise<VerifiablePresentation> {
        const { presentation, signatures, keyRef, ...otherOptions } = args
        const presCtx = processEntryToArray(presentation['@context'], MANDATORY_CREDENTIAL_CONTEXT)
        const presType = processEntryToArray(presentation.type, 'VerifiablePresentation')
        const normalized = { ...presentation, '@context': presCtx, type: presType }

        // coordinator DID/key to perform aggregation signing
        const managed = (await context.agent.didManagerFind())[0]
        if (!managed) throw new Error('no_managed_did: required for aggregation')
        const key =
            keyRef
                ? pickSigningKey(managed, keyRef)
                : (() => {
                      const blsKey = managed.keys.find((k) => k.type === 'Bls12381G1')
                      if (!blsKey) {
                          throw new Error(`key_not_found: No Bls12381G1 key for aggregation on ${managed.did}`)
                      }
                      return blsKey as IKey
                  })()
        const alg = 'BLS_AGGREGATE_MULTI_SIGNATURE'
        const signer = wrapSigner(context, key, alg)

        const vp = await aggregateMultiSignatureVerifiablePresentationBls(
            normalized as any,
            { did: managed.did, signer, alg },
            signatures,
            { ...otherOptions },
        )
        return normalizePresentation(vp)
    }

    /**
     * Creates a proof-of-ownership protected multisignature presentation.
     *
     * @public
     */
    async createProofOfOwnershipMultiHolderVerifiablePresentation(
        args: ICreateProofOfOwnershipMultiHolderVerifiablePresentationArgs,
        context: IssuerAgentContext,
    ): Promise<VerifiablePresentation> {
        const { presentation, signatures, proofsOfOwnership } = args
        const presCtx = processEntryToArray(presentation['@context'], MANDATORY_CREDENTIAL_CONTEXT)
        const presType = processEntryToArray(presentation.type, 'VerifiablePresentation')
        const normalized = { ...presentation, '@context': presCtx, type: presType }

        const vp = await generateProofOfOwnershipMultiIssuerVerifiablePresentationBls(
            normalized as any,
            proofsOfOwnership,
            signatures,
            undefined,
            this.blsBackend,
        )
        return vp;
    }

    /**
     * Verifies a multisignature presentation.
     *
     * @public
     */
    async verifyMultisignaturePresentation(
        args: IVerifyMultisignaturePresentationArgs,
        context: VerifierAgentContext,
    ): Promise<IVerifyResult> {
        const { presentation, ...otherOptions } = args
        return await verifyPresentationMultiSignatureBls(
            presentation,
            context,
            otherOptions?.resolutionOptions,
            this.blsBackend,
        )
    }

    /**
     * Verifies a proof-of-ownership protected multisignature presentation.
     *
     * @public
     */
    async verifyProofOfOwnershipMultisignaturePresentation(
        args: IVerifyProofOfOwnershipMultisignaturePresentationArgs,
        context: VerifierAgentContext,
    ): Promise<IVerifyResult> {
        const { presentation, ...otherOptions } = args
        return await verifyPresentationProofOfOwnershipMultiSignatureBls(
            presentation,
            context,
            otherOptions?.resolutionOptions,
            this.blsBackend,
        )
    }

}

function pickSigningKey(identifier: IIdentifier, keyRef?: string): IKey {
    let key: IKey | undefined

    if (!keyRef) {
        key = identifier.keys.find(
            (k) => k.type === 'Secp256k1' || k.type === 'Ed25519' || k.type === 'Secp256r1',
        )
        if (!key) throw Error('key_not_found: No signing key for ' + identifier.did)
    } else {
        key = identifier.keys.find((k) => k.kid === keyRef)
        if (!key) throw Error('key_not_found: No signing key for ' + identifier.did + ' with kid ' + keyRef)
    }

    return key as IKey
}

function wrapSigner(
    context: IAgentContext<Pick<IKeyManager, 'keyManagerSign'>>,
    key: IKey,
    algorithm?: string,
) {
    return async (data: string | Uint8Array): Promise<string> => {
        const result = await context.agent.keyManagerSign({ keyRef: key.kid, data: <string>data, algorithm })
        return result
    }
}

function detectDocumentType(document: W3CVerifiableCredential | W3CVerifiablePresentation): DocumentFormat {
    if (typeof document === 'string' || (<VerifiableCredential>document)?.proof?.jwt) return DocumentFormat.JWT
    if ((<VerifiableCredential>document)?.proof?.type === 'EthereumEip712Signature2021') return DocumentFormat.EIP712

    const ptype = (<any>document)?.proof?.type
    if (ptype === 'BlsSignaturePisa' || ptype === 'VPBlsMultiSignaturePisa' || ptype === 'VPProofOfOwnershipBlsMultiSignaturePisa') {
        return DocumentFormat.BLS
    }
    return DocumentFormat.JSONLD
}

async function isRevoked(
    credential: VerifiableCredential,
    context: IAgentContext<ICredentialStatusVerifier>,
): Promise<boolean> {
    if (!credential.credentialStatus) return false

    if (typeof context.agent.checkCredentialStatus === 'function') {
        const status = await context.agent.checkCredentialStatus({ credential })
        return status?.revoked == true || status?.verified === false
    }

    throw new Error(
        `invalid_setup: The credential status can't be verified because there is no ICredentialStatusVerifier plugin installed.`,
    )
}
