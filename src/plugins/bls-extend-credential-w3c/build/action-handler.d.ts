import { DIDResolutionOptions, IAgentPlugin, ICreateVerifiableCredentialArgs, ICreateVerifiablePresentationArgs, ICredentialPlugin, IIdentifier, IKey, IPluginMethodMap, IssuerAgentContext, IVerifyCredentialArgs, IVerifyPresentationArgs, IVerifyResult, ProofFormat, VerifiableCredential, VerifiablePresentation, VerifierAgentContext } from '@veramo/core-types';
type BlsBackend = 'chainsafe' | 'noble';
export type MultiIssuerVerifiableCredential = Omit<VerifiableCredential, 'issuer' | 'issuanceDate'> & {
    multi_issuers: string[];
};
export type MultiIssuerVerifiablePresentation = Omit<VerifiablePresentation, 'holder' | 'issuanceDate'> & {
    multi_holders: string[];
};
export type ProofOfOwnershipMultiIssuerVerifiableCredential = Omit<VerifiableCredential, 'issuer' | 'issuanceDate'> & {
    multi_issuers: string[];
    aggregated_bls_public_key: string;
};
export type ProofOfOwnershipMultiIssuerVerifiablePresentation = Omit<VerifiablePresentation, 'holder'> & {
    multi_holders: string[];
    aggregated_bls_public_key: string;
};
/**
 * Arguments for verifying a BLS multisignature credential.
 *
 * @public
 */
export interface IVerifyMultisignatureCredentialArgs {
    credential: MultiIssuerVerifiableCredential;
    policies?: IVerifyCredentialArgs['policies'];
    resolutionOptions?: DIDResolutionOptions & {
        publicKeyFormat?: string;
    };
}
/**
 * Arguments for verifying a proof-of-ownership protected BLS multisignature credential.
 *
 * @public
 */
export interface IVerifyProofOfOwnershipMultisignatureCredentialArgs {
    credential: ProofOfOwnershipMultiIssuerVerifiableCredential;
    policies?: IVerifyCredentialArgs['policies'];
    resolutionOptions?: DIDResolutionOptions & {
        publicKeyFormat?: string;
    };
}
/**
 * Arguments for collecting a partial BLS signature for a multi-issuer credential.
 *
 * @public
 */
export type ISignMultiIssuerVerifiableCredentialArgs = Omit<ICreateVerifiableCredentialArgs, 'issuer' | 'issuanceDate'> & {
    issuer: string;
};
/**
 * Arguments for aggregating issuer signatures into a multisigned credential.
 *
 * @public
 */
export interface ICreateMultiIssuerVerifiableCredentialArgs extends Omit<ICreateVerifiableCredentialArgs, 'issuer'> {
    issuer: string | {
        id: string;
    };
    signatures: string[];
}
/**
 * Arguments for creating a proof-of-ownership protected multisignature credential.
 *
 * @public
 */
export type ICreateProofOfOwnershipMultiIssuerVerifiableCredentialArgs = Omit<ICreateVerifiableCredentialArgs, 'issuer' | 'issuanceDate'> & {
    signatures: string[];
    proofsOfOwnership: string[];
};
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
    resolutionOptions?: DIDResolutionOptions & {
        publicKeyFormat?: string;
    };
}
/**
 * Arguments for verifying a proof-of-ownership protected BLS multisignature presentation.
 *
 * @public
 */
export interface IVerifyProofOfOwnershipMultisignaturePresentationArgs {
    presentation: ProofOfOwnershipMultiIssuerVerifiablePresentation;
    resolutionOptions?: DIDResolutionOptions & {
        publicKeyFormat?: string;
    };
}
export interface ICustomCredentialPlugin extends IPluginMethodMap {
    signMultiIssuedVerifiableCredential(args: ISignMultiIssuerVerifiableCredentialArgs, context: IssuerAgentContext): Promise<IMultisignatureSigningResult>;
    aggregateBlsPublicKeys(args: IAggregateBlsPublicKeysArgs, context: IssuerAgentContext): Promise<IAggregateBlsPublicKeysResult>;
    createMultiIssuerVerifiableCredential(args: ICreateMultiIssuerVerifiableCredentialArgs, context: IssuerAgentContext): Promise<VerifiableCredential>;
    createProofOfOwnershipMultiIssuerVerifiableCredential(args: ICreateProofOfOwnershipMultiIssuerVerifiableCredentialArgs, context: IssuerAgentContext): Promise<VerifiableCredential>;
    verifyMultisignatureCredential(args: IVerifyMultisignatureCredentialArgs, context: VerifierAgentContext): Promise<IVerifyResult>;
    verifyProofOfOwnershipMultisignatureCredential(args: IVerifyProofOfOwnershipMultisignatureCredentialArgs, context: VerifierAgentContext): Promise<IVerifyResult>;
    signMultiHolderVerifiablePresentation(args: ISignMultiHolderVerifiablePresentationArgs, context: IssuerAgentContext): Promise<IMultisignatureSigningResult>;
    createMultiHolderVerifiablePresentation(args: ICreateMultiHolderVerifiablePresentationArgs, context: IssuerAgentContext): Promise<VerifiablePresentation>;
    createProofOfOwnershipMultiHolderVerifiablePresentation(args: ICreateProofOfOwnershipMultiHolderVerifiablePresentationArgs, context: IssuerAgentContext): Promise<VerifiablePresentation>;
    verifyMultisignaturePresentation(args: IVerifyMultisignaturePresentationArgs, context: VerifierAgentContext): Promise<IVerifyResult>;
    verifyProofOfOwnershipMultisignaturePresentation(args: IVerifyProofOfOwnershipMultisignaturePresentationArgs, context: VerifierAgentContext): Promise<IVerifyResult>;
}
/**
 * A Veramo plugin that implements the {@link @veramo/core-types#ICredentialPlugin | ICredentialPlugin} methods.
 *
 * @public
 */
export declare class CredentialPlugin implements IAgentPlugin {
    readonly methods: ICredentialPlugin & ICustomCredentialPlugin;
    private readonly blsBackend;
    readonly schema: {
        components: {
            schemas: {
                IVerifyCredentialArgs: {
                    type: string;
                    properties: {
                        resolutionOptions: {
                            type: string;
                            properties: {
                                publicKeyFormat: {
                                    type: string;
                                };
                                accept: {
                                    type: string;
                                };
                            };
                            description: string;
                        };
                        credential: {
                            $ref: string;
                            description: string;
                        };
                        fetchRemoteContexts: {
                            type: string;
                            description: string;
                        };
                        policies: {
                            $ref: string;
                            description: string;
                        };
                    };
                    required: string[];
                    additionalProperties: {
                        description: string;
                    };
                    description: string;
                };
                W3CVerifiableCredential: {
                    anyOf: {
                        $ref: string;
                    }[];
                    description: string;
                };
                VerifiableCredential: {
                    type: string;
                    properties: {
                        proof: {
                            $ref: string;
                        };
                        issuer: {
                            $ref: string;
                        };
                        credentialSubject: {
                            $ref: string;
                        };
                        type: {
                            anyOf: ({
                                type: string;
                                items: {
                                    type: string;
                                };
                            } | {
                                type: string;
                                items?: undefined;
                            })[];
                        };
                        "@context": {
                            $ref: string;
                        };
                        issuanceDate: {
                            type: string;
                        };
                        expirationDate: {
                            type: string;
                        };
                        credentialStatus: {
                            $ref: string;
                        };
                        id: {
                            type: string;
                        };
                    };
                    required: string[];
                    description: string;
                };
                ProofType: {
                    type: string;
                    properties: {
                        type: {
                            type: string;
                        };
                    };
                    description: string;
                };
                IssuerType: {
                    anyOf: ({
                        type: string;
                        properties: {
                            id: {
                                type: string;
                            };
                        };
                        required: string[];
                    } | {
                        type: string;
                        properties?: undefined;
                        required?: undefined;
                    })[];
                    description: string;
                };
                CredentialSubject: {
                    type: string;
                    properties: {
                        id: {
                            type: string;
                        };
                    };
                    description: string;
                };
                ContextType: {
                    anyOf: ({
                        type: string;
                        items?: undefined;
                    } | {
                        type: string;
                        items: {
                            anyOf: {
                                type: string;
                            }[];
                        };
                    })[];
                    description: string;
                };
                CredentialStatusReference: {
                    type: string;
                    properties: {
                        id: {
                            type: string;
                        };
                        type: {
                            type: string;
                        };
                    };
                    required: string[];
                    description: string;
                };
                CompactJWT: {
                    type: string;
                    description: string;
                };
                VerificationPolicies: {
                    type: string;
                    properties: {
                        now: {
                            type: string;
                            description: string;
                        };
                        issuanceDate: {
                            type: string;
                            description: string;
                        };
                        expirationDate: {
                            type: string;
                            description: string;
                        };
                        audience: {
                            type: string;
                            description: string;
                        };
                        credentialStatus: {
                            type: string;
                            description: string;
                        };
                    };
                    additionalProperties: {
                        description: string;
                    };
                    description: string;
                };
                IVerifyResult: {
                    type: string;
                    properties: {
                        verified: {
                            type: string;
                            description: string;
                        };
                        error: {
                            $ref: string;
                            description: string;
                        };
                    };
                    required: string[];
                    additionalProperties: {
                        description: string;
                    };
                    description: string;
                };
                IError: {
                    type: string;
                    properties: {
                        message: {
                            type: string;
                            description: string;
                        };
                        errorCode: {
                            type: string;
                            description: string;
                        };
                    };
                    description: string;
                };
                IVerifyPresentationArgs: {
                    type: string;
                    properties: {
                        resolutionOptions: {
                            type: string;
                            properties: {
                                publicKeyFormat: {
                                    type: string;
                                };
                                accept: {
                                    type: string;
                                };
                            };
                            description: string;
                        };
                        presentation: {
                            $ref: string;
                            description: string;
                        };
                        challenge: {
                            type: string;
                            description: string;
                        };
                        domain: {
                            type: string;
                            description: string;
                        };
                        fetchRemoteContexts: {
                            type: string;
                            description: string;
                        };
                        policies: {
                            $ref: string;
                            description: string;
                        };
                    };
                    required: string[];
                    additionalProperties: {
                        description: string;
                    };
                    description: string;
                };
                W3CVerifiablePresentation: {
                    anyOf: {
                        $ref: string;
                    }[];
                    description: string;
                };
                VerifiablePresentation: {
                    type: string;
                    properties: {
                        proof: {
                            $ref: string;
                        };
                        holder: {
                            type: string;
                        };
                        verifiableCredential: {
                            type: string;
                            items: {
                                $ref: string;
                            };
                        };
                        type: {
                            anyOf: ({
                                type: string;
                                items: {
                                    type: string;
                                };
                            } | {
                                type: string;
                                items?: undefined;
                            })[];
                        };
                        "@context": {
                            $ref: string;
                        };
                        verifier: {
                            type: string;
                            items: {
                                type: string;
                            };
                        };
                        issuanceDate: {
                            type: string;
                        };
                        expirationDate: {
                            type: string;
                        };
                        id: {
                            type: string;
                        };
                    };
                    required: string[];
                    description: string;
                };
                ICreateVerifiableCredentialArgs: {
                    type: string;
                    properties: {
                        resolutionOptions: {
                            type: string;
                            properties: {
                                publicKeyFormat: {
                                    type: string;
                                };
                                accept: {
                                    type: string;
                                };
                            };
                            description: string;
                        };
                        credential: {
                            $ref: string;
                            description: string;
                        };
                        save: {
                            type: string;
                            description: string;
                            deprecated: string;
                        };
                        proofFormat: {
                            $ref: string;
                            description: string;
                        };
                        removeOriginalFields: {
                            type: string;
                            description: string;
                        };
                        keyRef: {
                            type: string;
                            description: string;
                        };
                        fetchRemoteContexts: {
                            type: string;
                            description: string;
                        };
                    };
                    required: string[];
                    additionalProperties: {
                        description: string;
                    };
                    description: string;
                };
                CredentialPayload: {
                    type: string;
                    properties: {
                        issuer: {
                            $ref: string;
                        };
                        credentialSubject: {
                            $ref: string;
                        };
                        type: {
                            type: string;
                            items: {
                                type: string;
                            };
                        };
                        "@context": {
                            $ref: string;
                        };
                        issuanceDate: {
                            $ref: string;
                        };
                        expirationDate: {
                            $ref: string;
                        };
                        credentialStatus: {
                            $ref: string;
                        };
                        id: {
                            type: string;
                        };
                    };
                    required: string[];
                    description: string;
                };
                DateType: {
                    type: string;
                    description: string;
                };
                ProofFormat: {
                    type: string;
                    enum: string[];
                    description: string;
                };
                ICreateVerifiablePresentationArgs: {
                    type: string;
                    properties: {
                        resolutionOptions: {
                            type: string;
                            properties: {
                                publicKeyFormat: {
                                    type: string;
                                };
                                accept: {
                                    type: string;
                                };
                            };
                            description: string;
                        };
                        presentation: {
                            $ref: string;
                            description: string;
                        };
                        save: {
                            type: string;
                            description: string;
                            deprecated: string;
                        };
                        challenge: {
                            type: string;
                            description: string;
                        };
                        domain: {
                            type: string;
                            description: string;
                        };
                        proofFormat: {
                            $ref: string;
                            description: string;
                        };
                        removeOriginalFields: {
                            type: string;
                            description: string;
                        };
                        keyRef: {
                            type: string;
                            description: string;
                        };
                        fetchRemoteContexts: {
                            type: string;
                            description: string;
                        };
                    };
                    required: string[];
                    additionalProperties: {
                        description: string;
                    };
                    description: string;
                };
                PresentationPayload: {
                    type: string;
                    properties: {
                        holder: {
                            type: string;
                        };
                        verifiableCredential: {
                            type: string;
                            items: {
                                $ref: string;
                            };
                        };
                        type: {
                            type: string;
                            items: {
                                type: string;
                            };
                        };
                        "@context": {
                            $ref: string;
                        };
                        verifier: {
                            type: string;
                            items: {
                                type: string;
                            };
                        };
                        issuanceDate: {
                            $ref: string;
                        };
                        expirationDate: {
                            $ref: string;
                        };
                        id: {
                            type: string;
                        };
                    };
                    required: string[];
                    description: string;
                };
                IIdentifier: {
                    type: string;
                    properties: {
                        did: {
                            type: string;
                            description: string;
                        };
                        alias: {
                            type: string;
                            description: string;
                        };
                        provider: {
                            type: string;
                            description: string;
                        };
                        controllerKeyId: {
                            type: string;
                            description: string;
                        };
                        keys: {
                            type: string;
                            items: {
                                $ref: string;
                            };
                            description: string;
                        };
                        services: {
                            type: string;
                            items: {
                                $ref: string;
                            };
                            description: string;
                        };
                    };
                    required: string[];
                    description: string;
                };
                IKey: {
                    type: string;
                    properties: {
                        kid: {
                            type: string;
                            description: string;
                        };
                        kms: {
                            type: string;
                            description: string;
                        };
                        type: {
                            $ref: string;
                            description: string;
                        };
                        publicKeyHex: {
                            type: string;
                            description: string;
                        };
                        privateKeyHex: {
                            type: string;
                            description: string;
                        };
                        meta: {
                            anyOf: ({
                                $ref: string;
                                type?: undefined;
                            } | {
                                type: string;
                                $ref?: undefined;
                            })[];
                            description: string;
                        };
                    };
                    required: string[];
                    description: string;
                };
                TKeyType: {
                    type: string;
                    enum: string[];
                    description: string;
                };
                KeyMetadata: {
                    type: string;
                    properties: {
                        algorithms: {
                            type: string;
                            items: {
                                $ref: string;
                            };
                        };
                    };
                    description: string;
                };
                TAlg: {
                    type: string;
                    description: string;
                };
                IService: {
                    type: string;
                    properties: {
                        id: {
                            type: string;
                            description: string;
                        };
                        type: {
                            type: string;
                            description: string;
                        };
                        serviceEndpoint: {
                            anyOf: ({
                                $ref: string;
                                type?: undefined;
                                items?: undefined;
                            } | {
                                type: string;
                                items: {
                                    $ref: string;
                                };
                                $ref?: undefined;
                            })[];
                            description: string;
                        };
                        description: {
                            type: string;
                            description: string;
                        };
                    };
                    required: string[];
                    description: string;
                };
                IServiceEndpoint: {
                    anyOf: {
                        type: string;
                    }[];
                    description: string;
                };
            };
            methods: {
                signMultiIssuedVerifiableCredential: {
                    description: string;
                    arguments: {
                        type: string;
                        properties: {
                            credential: {
                                type: string;
                            };
                            proofFormat: {
                                type: string;
                            };
                            keyRef: {
                                type: string;
                            };
                            save: {
                                type: string;
                            };
                            now: {
                                type: string;
                            };
                        };
                        required: string[];
                    };
                    returns: {
                        type: string;
                        properties: {
                            signatureData: {
                                type: string;
                                properties: {
                                    payloadToSign: {
                                        type: string;
                                    };
                                    signatureHex: {
                                        type: string;
                                    };
                                };
                                required: string[];
                            };
                        };
                        required: string[];
                    };
                };
                aggregateBlsPublicKeys: {
                    description: string;
                    arguments: {
                        type: string;
                        properties: {
                            list_of_publicKeyHex: {
                                type: string;
                                items: {
                                    type: string;
                                };
                            };
                        };
                        required: string[];
                    };
                    returns: {
                        type: string;
                        properties: {
                            bls_aggregated_pubkey: {
                                type: string;
                            };
                        };
                        required: string[];
                    };
                };
                createMultiIssuerVerifiableCredential: {
                    description: string;
                    arguments: {
                        type: string;
                        properties: {
                            credential: {
                                type: string;
                            };
                            proofFormat: {
                                type: string;
                            };
                            issuer: {
                                oneOf: ({
                                    type: string;
                                    properties?: undefined;
                                    required?: undefined;
                                } | {
                                    type: string;
                                    properties: {
                                        id: {
                                            type: string;
                                        };
                                    };
                                    required: string[];
                                })[];
                            };
                            keyRef: {
                                type: string;
                            };
                            signatures: {
                                type: string;
                                items: {
                                    type: string;
                                };
                            };
                            save: {
                                type: string;
                            };
                            now: {
                                type: string;
                            };
                        };
                        required: string[];
                    };
                    returns: {
                        type: string;
                    };
                };
                createProofOfOwnershipMultiIssuerVerifiableCredential: {
                    description: string;
                    arguments: {
                        type: string;
                        properties: {
                            credential: {
                                type: string;
                            };
                            proofFormat: {
                                type: string;
                            };
                            signatures: {
                                type: string;
                                items: {
                                    type: string;
                                };
                            };
                            proofsOfOwnership: {
                                type: string;
                                items: {
                                    type: string;
                                };
                            };
                        };
                        required: string[];
                    };
                    returns: {
                        type: string;
                    };
                };
                verifyMultisignatureCredential: {
                    description: string;
                    arguments: {
                        type: string;
                        properties: {
                            credential: {
                                type: string;
                            };
                            policies: {
                                type: string;
                            };
                            resolutionOptions: {
                                type: string;
                            };
                        };
                        required: string[];
                    };
                    returns: {
                        type: string;
                    };
                };
                verifyProofOfOwnershipMultisignatureCredential: {
                    description: string;
                    arguments: {
                        type: string;
                        properties: {
                            credential: {
                                type: string;
                            };
                            policies: {
                                type: string;
                            };
                            resolutionOptions: {
                                type: string;
                            };
                        };
                        required: string[];
                    };
                    returns: {
                        type: string;
                    };
                };
                signMultiHolderVerifiablePresentation: {
                    description: string;
                    arguments: {
                        type: string;
                        properties: {
                            presentation: {
                                type: string;
                            };
                            holder: {
                                type: string;
                            };
                            keyRef: {
                                type: string;
                            };
                        };
                        required: string[];
                    };
                    returns: {
                        type: string;
                        properties: {
                            signatureData: {
                                type: string;
                                properties: {
                                    payloadToSign: {
                                        type: string;
                                    };
                                    signatureHex: {
                                        type: string;
                                    };
                                };
                                required: string[];
                            };
                        };
                        required: string[];
                    };
                };
                createMultiHolderVerifiablePresentation: {
                    description: string;
                    arguments: {
                        type: string;
                        properties: {
                            presentation: {
                                type: string;
                            };
                            signatures: {
                                type: string;
                                items: {
                                    type: string;
                                };
                            };
                            keyRef: {
                                type: string;
                            };
                        };
                        required: string[];
                    };
                    returns: {
                        type: string;
                    };
                };
                createProofOfOwnershipMultiHolderVerifiablePresentation: {
                    description: string;
                    arguments: {
                        type: string;
                        properties: {
                            presentation: {
                                type: string;
                            };
                            signatures: {
                                type: string;
                                items: {
                                    type: string;
                                };
                            };
                            proofsOfOwnership: {
                                type: string;
                                items: {
                                    type: string;
                                };
                            };
                        };
                        required: string[];
                    };
                    returns: {
                        type: string;
                    };
                };
                verifyMultisignaturePresentation: {
                    description: string;
                    arguments: {
                        type: string;
                        properties: {
                            presentation: {
                                type: string;
                            };
                            resolutionOptions: {
                                type: string;
                            };
                        };
                        required: string[];
                    };
                    returns: {
                        type: string;
                    };
                };
                verifyProofOfOwnershipMultisignaturePresentation: {
                    description: string;
                    arguments: {
                        type: string;
                        properties: {
                            presentation: {
                                type: string;
                            };
                            resolutionOptions: {
                                type: string;
                            };
                        };
                        required: string[];
                    };
                    returns: {
                        type: string;
                    };
                };
                verifyCredential: {
                    description: string;
                    arguments: {
                        $ref: string;
                    };
                    returnType: {
                        $ref: string;
                    };
                };
                verifyPresentation: {
                    description: string;
                    arguments: {
                        $ref: string;
                    };
                    returnType: {
                        $ref: string;
                    };
                };
                createVerifiableCredential: {
                    description: string;
                    arguments: {
                        $ref: string;
                    };
                    returnType: {
                        $ref: string;
                    };
                };
                createVerifiablePresentation: {
                    description: string;
                    arguments: {
                        $ref: string;
                    };
                    returnType: {
                        $ref: string;
                    };
                };
                listUsableProofFormats: {
                    description: string;
                    arguments: {
                        $ref: string;
                    };
                    returnType: {
                        type: string;
                        items: {
                            $ref: string;
                        };
                    };
                };
            };
        };
    };
    constructor(options?: {
        blsBackend?: BlsBackend;
    } & Record<string, any>);
    /**
     * Verifies a multisignature credential using the issuer list embedded in the document.
     *
     * @public
     */
    verifyMultisignatureCredential(args: IVerifyMultisignatureCredentialArgs, context: VerifierAgentContext): Promise<IVerifyResult>;
    /**
     * Verifies a proof-of-ownership protected multisignature credential.
     *
     * @public
     */
    verifyProofOfOwnershipMultisignatureCredential(args: IVerifyProofOfOwnershipMultisignatureCredentialArgs, context: VerifierAgentContext): Promise<IVerifyResult>;
    /** {@inheritdoc @veramo/core-types#ICredentialIssuer.createVerifiablePresentation} */
    createVerifiablePresentation(args: ICreateVerifiablePresentationArgs, context: IssuerAgentContext): Promise<VerifiablePresentation>;
    /**
     * Aggregates multiple BLS public keys into a single public key.
     *
     * @public
     */
    aggregateBlsPublicKeys(args: IAggregateBlsPublicKeysArgs, context: IssuerAgentContext): Promise<IAggregateBlsPublicKeysResult>;
    /**
     * Collects a partial BLS signature for a multi-issuer credential payload.
     *
     * @public
     */
    signMultiIssuedVerifiableCredential(args: ISignMultiIssuerVerifiableCredentialArgs, context: IssuerAgentContext): Promise<IMultisignatureSigningResult>;
    /**
     * Aggregates multiple issuer signatures into a final multisignature credential.
     *
     * @public
     */
    createMultiIssuerVerifiableCredential(args: ICreateMultiIssuerVerifiableCredentialArgs, context: IssuerAgentContext): Promise<VerifiableCredential>;
    /**
     * Creates a proof-of-ownership protected multisignature credential.
     *
     * @public
     */
    createProofOfOwnershipMultiIssuerVerifiableCredential(args: ICreateProofOfOwnershipMultiIssuerVerifiableCredentialArgs, context: IssuerAgentContext): Promise<VerifiableCredential>;
    /** {@inheritdoc @veramo/core-types#ICredentialIssuer.createVerifiableCredential} */
    createVerifiableCredential(args: ICreateVerifiableCredentialArgs, context: IssuerAgentContext): Promise<VerifiableCredential>;
    /** {@inheritdoc @veramo/core-types#ICredentialVerifier.verifyCredential} */
    verifyCredential(args: IVerifyCredentialArgs, context: VerifierAgentContext): Promise<IVerifyResult>;
    /** {@inheritdoc @veramo/core-types#ICredentialVerifier.verifyPresentation} */
    verifyPresentation(args: IVerifyPresentationArgs, context: VerifierAgentContext): Promise<IVerifyResult>;
    /**
     * Checks if a key is suitable for signing JWT payloads.
     * @param key - the key to check
     * @param context - the Veramo agent context, unused here
     *
     * @beta
     */
    matchKeyForJWT(key: IKey, context: IssuerAgentContext): Promise<boolean>;
    listUsableProofFormats(did: IIdentifier, context: IssuerAgentContext): Promise<ProofFormat[]>;
    /**
     * Collects a partial BLS signature for a multi-holder presentation payload.
     *
     * @public
     */
    signMultiHolderVerifiablePresentation(args: ISignMultiHolderVerifiablePresentationArgs, context: IssuerAgentContext): Promise<IMultisignatureSigningResult>;
    /**
     * Aggregates holder signatures into a final multisignature presentation.
     *
     * @public
     */
    createMultiHolderVerifiablePresentation(args: ICreateMultiHolderVerifiablePresentationArgs, context: IssuerAgentContext): Promise<VerifiablePresentation>;
    /**
     * Creates a proof-of-ownership protected multisignature presentation.
     *
     * @public
     */
    createProofOfOwnershipMultiHolderVerifiablePresentation(args: ICreateProofOfOwnershipMultiHolderVerifiablePresentationArgs, context: IssuerAgentContext): Promise<VerifiablePresentation>;
    /**
     * Verifies a multisignature presentation.
     *
     * @public
     */
    verifyMultisignaturePresentation(args: IVerifyMultisignaturePresentationArgs, context: VerifierAgentContext): Promise<IVerifyResult>;
    /**
     * Verifies a proof-of-ownership protected multisignature presentation.
     *
     * @public
     */
    verifyProofOfOwnershipMultisignaturePresentation(args: IVerifyProofOfOwnershipMultisignaturePresentationArgs, context: VerifierAgentContext): Promise<IVerifyResult>;
}
export {};
