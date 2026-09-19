//new: the standard proof formats are delegated to the official Veramo CredentialPlugin and its providers
//new: this plugin owns the BLS multi-signature operations: partial signing, aggregation and proof of ownership

import {
  DIDResolutionOptions,
  IAgentPlugin,
  ICreateVerifiableCredentialArgs,
  ICreateVerifiablePresentationArgs,
  ICredentialPlugin,
  IIdentifier,
  IKey,
  IPluginMethodMap,
  IssuerAgentContext,
  IVerifyCredentialArgs,
  IVerifyResult,
  ProofFormat,
  schema,
  VerifiableCredential,
  VerifiablePresentation,
  VerifierAgentContext,
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
  | 'ProofOfOwnership-aggregate-bls-multi-signature-vp'

import { CredentialPlugin as W3cCredentialPlugin } from '@veramo/credential-w3c'
import type { ICredentialProvider } from '@veramo/credential-w3c'
import { CredentialProviderJWT } from '@veramo/credential-jwt'

import { normalizeCredential, normalizePresentation } from 'did-jwt-vc'

import { BlsCrypto, resolveBlsBackend } from '@veramo-community/kms-local-bls'

import {
  signMultiSignatureVerifiableCredentialBls,
  aggregateMultiSignatureVerifiableCredentialBls,
  verifyCredentialMultiSignatureBls,
  generateProofOfOwnershipMultiIssuerVerifiableCredentialBls,
  verifyCredentialProofOfOwnershipMultiSignatureBls,
} from './bls-credentials.js'

import {
  signMultiSignatureVerifiablePresentationBls,
  aggregateMultiSignatureVerifiablePresentationBls,
  verifyPresentationMultiSignatureBls,
  generateProofOfOwnershipMultiIssuerVerifiablePresentationBls,
  verifyPresentationProofOfOwnershipMultiSignatureBls,
} from './bls-presentations.js'

import {
  CredentialProviderBls,
  withCredentialContextAndType,
  withPresentationContextAndType,
} from './bls-credential-provider.js'
import type { BlsBackend } from './bls-credential-provider.js'
import { pickSigningKey, wrapSigner } from './signing-keys.js'

export type { BlsBackend }

/** KMS algorithms behind the two steps of a multi-signature: each issuer signs, one party aggregates. */
const PARTIAL_SIGNATURE_ALG = 'BLS_SIGNATURE'
const AGGREGATE_SIGNATURE_ALG = 'BLS_AGGREGATE_MULTI_SIGNATURE'

export type MultiIssuerVerifiableCredential = Omit<
  VerifiableCredential,
  'issuer' | 'issuanceDate'
> & {
  multi_issuers: string[]
}
export type MultiIssuerVerifiablePresentation = Omit<
  VerifiablePresentation,
  'holder' | 'issuanceDate'
> & {
  multi_holders: string[]
}

export type ProofOfOwnershipMultiIssuerVerifiableCredential = Omit<
  VerifiableCredential,
  'issuer' | 'issuanceDate'
> & {
  multi_issuers: string[]
  aggregated_bls_public_key: string
}
export type ProofOfOwnershipMultiIssuerVerifiablePresentation = Omit<
  VerifiablePresentation,
  'holder'
> & {
  multi_holders: string[]
  aggregated_bls_public_key: string
}

/**
 * Arguments for verifying a BLS multisignature credential.
 *
 * @public
 */
export interface IVerifyMultisignatureCredentialArgs {
  credential: MultiIssuerVerifiableCredential
  policies?: IVerifyCredentialArgs['policies']
  resolutionOptions?: DIDResolutionOptions & { publicKeyFormat?: string }
}

/**
 * Arguments for verifying a proof-of-ownership protected BLS multisignature credential.
 *
 * @public
 */
export interface IVerifyProofOfOwnershipMultisignatureCredentialArgs {
  credential: ProofOfOwnershipMultiIssuerVerifiableCredential
  policies?: IVerifyCredentialArgs['policies']
  resolutionOptions?: DIDResolutionOptions & { publicKeyFormat?: string }
}

/**
 * Arguments for collecting a partial BLS signature for a multi-issuer credential.
 *
 * @public
 */
export type ISignMultiIssuerVerifiableCredentialArgs = Omit<
  ICreateVerifiableCredentialArgs,
  'issuer' | 'issuanceDate'
> & {
  issuer: string
}

/**
 * Arguments for aggregating issuer signatures into a multisigned credential.
 *
 * @public
 */
export interface ICreateMultiIssuerVerifiableCredentialArgs
  extends Omit<ICreateVerifiableCredentialArgs, 'issuer'> {
  issuer: string | { id: string }
  signatures: string[]
}

/**
 * Arguments for creating a proof-of-ownership protected multisignature credential.
 *
 * @public
 */
export type ICreateProofOfOwnershipMultiIssuerVerifiableCredentialArgs = Omit<
  ICreateVerifiableCredentialArgs,
  'issuer' | 'issuanceDate'
> & {
  signatures: string[]
  proofsOfOwnership: string[]
}

/**
 * Arguments for aggregating BLS public keys.
 *
 * @public
 */
export interface IAggregateBlsPublicKeysArgs {
  list_of_publicKeyHex: string[]
}

/**
 * Result returned by the BLS public key aggregation helper.
 *
 * @public
 */
export interface IAggregateBlsPublicKeysResult {
  bls_aggregated_pubkey: string
}

/**
 * A serializable partial multisignature fragment.
 *
 * @public
 */
export interface IMultisignatureFragment {
  payloadToSign: string
  signatureHex: string
}

/**
 * Result returned when collecting a partial multisignature.
 *
 * @public
 */
export interface IMultisignatureSigningResult {
  signatureData: IMultisignatureFragment
}

/**
 * Arguments for collecting a partial BLS signature for a multi-holder presentation.
 *
 * @public
 */
export interface ISignMultiHolderVerifiablePresentationArgs
  extends ICreateVerifiablePresentationArgs {
  holder: string
}

/**
 * Arguments for aggregating holder signatures into a multisigned presentation.
 *
 * @public
 */
export interface ICreateMultiHolderVerifiablePresentationArgs
  extends ICreateVerifiablePresentationArgs {
  signatures: string[]
}

/**
 * Arguments for creating a proof-of-ownership protected multisignature presentation.
 *
 * @public
 */
export interface ICreateProofOfOwnershipMultiHolderVerifiablePresentationArgs
  extends ICreateVerifiablePresentationArgs {
  signatures: string[]
  proofsOfOwnership: string[]
}

/**
 * Arguments for verifying a BLS multisignature presentation.
 *
 * @public
 */
export interface IVerifyMultisignaturePresentationArgs {
  presentation: MultiIssuerVerifiablePresentation
  resolutionOptions?: DIDResolutionOptions & { publicKeyFormat?: string }
}

/**
 * Arguments for verifying a proof-of-ownership protected BLS multisignature presentation.
 *
 * @public
 */
export interface IVerifyProofOfOwnershipMultisignaturePresentationArgs {
  presentation: ProofOfOwnershipMultiIssuerVerifiablePresentation
  resolutionOptions?: DIDResolutionOptions & { publicKeyFormat?: string }
}

export interface ICustomCredentialPlugin extends IPluginMethodMap {
  // VC (multi-issuer)
  signMultiIssuedVerifiableCredential(
    args: ISignMultiIssuerVerifiableCredentialArgs,
    context: IssuerAgentContext,
  ): Promise<IMultisignatureSigningResult>

  aggregateBlsPublicKeys(
    args: IAggregateBlsPublicKeysArgs,
    context: IssuerAgentContext,
  ): Promise<IAggregateBlsPublicKeysResult>

  createMultiIssuerVerifiableCredential(
    args: ICreateMultiIssuerVerifiableCredentialArgs,
    context: IssuerAgentContext,
  ): Promise<VerifiableCredential>

  createProofOfOwnershipMultiIssuerVerifiableCredential(
    args: ICreateProofOfOwnershipMultiIssuerVerifiableCredentialArgs,
    context: IssuerAgentContext,
  ): Promise<VerifiableCredential>

  verifyMultisignatureCredential(
    args: IVerifyMultisignatureCredentialArgs,
    context: VerifierAgentContext,
  ): Promise<IVerifyResult>

  verifyProofOfOwnershipMultisignatureCredential(
    args: IVerifyProofOfOwnershipMultisignatureCredentialArgs,
    context: VerifierAgentContext,
  ): Promise<IVerifyResult>

  signMultiHolderVerifiablePresentation(
    args: ISignMultiHolderVerifiablePresentationArgs,
    context: IssuerAgentContext,
  ): Promise<IMultisignatureSigningResult>

  createMultiHolderVerifiablePresentation(
    args: ICreateMultiHolderVerifiablePresentationArgs,
    context: IssuerAgentContext,
  ): Promise<VerifiablePresentation>

  createProofOfOwnershipMultiHolderVerifiablePresentation(
    args: ICreateProofOfOwnershipMultiHolderVerifiablePresentationArgs,
    context: IssuerAgentContext,
  ): Promise<VerifiablePresentation>

  verifyMultisignaturePresentation(
    args: IVerifyMultisignaturePresentationArgs,
    context: VerifierAgentContext,
  ): Promise<IVerifyResult>

  verifyProofOfOwnershipMultisignaturePresentation(
    args: IVerifyProofOfOwnershipMultisignaturePresentationArgs,
    context: VerifierAgentContext,
  ): Promise<IVerifyResult>

  /** Kept from the Veramo 6 ICredentialIssuer surface, callers still ask the agent for it. */
  matchKeyForJWT(key: IKey, context: IssuerAgentContext): Promise<boolean>
}

/**
 * A Veramo plugin that implements the {@link @veramo/core-types#ICredentialPlugin | ICredentialPlugin} methods
 * and adds the BLS multi-signature operations.
 *
 * @public
 */
export class CredentialPlugin implements IAgentPlugin {
  readonly methods: ICredentialPlugin & ICustomCredentialPlugin
  private readonly blsBackend: BlsBackend
  private readonly providers: ICredentialProvider[]
  private readonly w3cPlugin: W3cCredentialPlugin
  readonly schema = {
    components: {
      schemas: {
        ...schema.ICredentialIssuer.components.schemas,
        ...schema.ICredentialVerifier.components.schemas,
      },
      methods: {
        ...schema.ICredentialIssuer.components.methods,
        ...schema.ICredentialVerifier.components.methods,

        matchKeyForJWT: {
          description: 'Checks if a key is suitable for signing JWT payloads',
          arguments: { type: 'object' },
          returnType: { type: 'boolean' },
        },
        signMultiIssuedVerifiableCredential: {
          description:
            'Signs a credential with BLS or other proof format in a multi-issuer scenario',
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
          returnType: {
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
          description:
            'Aggregates multiple BLS public keys into one public key',
          arguments: {
            type: 'object',
            properties: {
              list_of_publicKeyHex: {
                type: 'array',
                items: { type: 'string' },
              },
            },
            required: ['list_of_publicKeyHex'],
          },
          returnType: {
            type: 'object',
            properties: {
              bls_aggregated_pubkey: { type: 'string' },
            },
            required: ['bls_aggregated_pubkey'],
          },
        },
        createMultiIssuerVerifiableCredential: {
          description:
            'Aggregates BLS signatures from multiple issuers and produces a final Verifiable Credential',
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
          returnType: {
            type: 'object',
          },
        },
        createProofOfOwnershipMultiIssuerVerifiableCredential: {
          description:
            'Creates a proof-of-ownership protected multisignature credential',
          arguments: {
            type: 'object',
            properties: {
              credential: { type: 'object' },
              proofFormat: { type: 'string' },
              signatures: { type: 'array', items: { type: 'string' } },
              proofsOfOwnership: { type: 'array', items: { type: 'string' } },
            },
            required: [
              'credential',
              'proofFormat',
              'signatures',
              'proofsOfOwnership',
            ],
          },
          returnType: {
            type: 'object',
          },
        },
        verifyMultisignatureCredential: {
          description:
            'Verifies a multi-signature BLS credential without issuer, using multi_issuers[] instead',
          arguments: {
            type: 'object',
            properties: {
              credential: { type: 'object' },
              policies: { type: 'object' },
              resolutionOptions: { type: 'object' },
            },
            required: ['credential'],
          },
          returnType: {
            type: 'object',
          },
        },
        verifyProofOfOwnershipMultisignatureCredential: {
          description:
            'Verifies a proof-of-ownership protected multisignature credential',
          arguments: {
            type: 'object',
            properties: {
              credential: { type: 'object' },
              policies: { type: 'object' },
              resolutionOptions: { type: 'object' },
            },
            required: ['credential'],
          },
          returnType: {
            type: 'object',
          },
        },
        signMultiHolderVerifiablePresentation: {
          description: 'Collect a BLS partial signature for a multi-holder VP',
          arguments: {
            type: 'object',
            properties: {
              presentation: { type: 'object' },
              holder: { type: 'string' },
              keyRef: { type: 'string' },
            },
            required: ['presentation', 'holder'],
          },
          returnType: {
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
          description:
            'Aggregate BLS partial signatures into a multi-holder VP',
          arguments: {
            type: 'object',
            properties: {
              presentation: { type: 'object' },
              signatures: { type: 'array', items: { type: 'string' } },
              keyRef: { type: 'string' },
            },
            required: ['presentation', 'signatures'],
          },
          returnType: { type: 'object' },
        },
        createProofOfOwnershipMultiHolderVerifiablePresentation: {
          description: 'Attach PoO & aggregated BLS sig to VP (multi-holder)',
          arguments: {
            type: 'object',
            properties: {
              presentation: { type: 'object' },
              signatures: { type: 'array', items: { type: 'string' } },
              proofsOfOwnership: { type: 'array', items: { type: 'string' } },
            },
            required: ['presentation', 'signatures', 'proofsOfOwnership'],
          },
          returnType: { type: 'object' },
        },
        verifyMultisignaturePresentation: {
          description: 'Verify multi-holder VP aggregated BLS signature',
          arguments: {
            type: 'object',
            properties: {
              presentation: { type: 'object' },
              resolutionOptions: { type: 'object' },
            },
            required: ['presentation'],
          },
          returnType: { type: 'object' },
        },
        verifyProofOfOwnershipMultisignaturePresentation: {
          description: 'Verify multi-holder VP PoO + aggregated BLS signature',
          arguments: {
            type: 'object',
            properties: {
              presentation: { type: 'object' },
              resolutionOptions: { type: 'object' },
            },
            required: ['presentation'],
          },
          returnType: { type: 'object' },
        },
      },
    },
  }

  constructor(
    options?: {
      blsBackend?: BlsBackend
      providers?: ICredentialProvider[]
    } & Record<string, any>,
  ) {
    this.blsBackend = resolveBlsBackend(options?.blsBackend)
    // BLS first, then the official JWT provider. Providers for the remaining standard formats
    // (lds, EthereumEip712Signature2021) are supplied by the caller and consulted last.
    this.providers = [
      new CredentialProviderBls({ blsBackend: this.blsBackend }),
      new CredentialProviderJWT(),
      ...(options?.providers ?? []),
    ]
    this.w3cPlugin = new W3cCredentialPlugin(this.providers)
    this.methods = {
      // createVerifiableCredential, verifyCredential, createVerifiablePresentation,
      // verifyPresentation and listUsableProofFormats come from the official plugin,
      // which routes each document to the provider that can handle it.
      ...this.w3cPlugin.methods,
      matchKeyForJWT: this.matchKeyForJWT.bind(this),

      // Added custom NEW function
      signMultiIssuedVerifiableCredential:
        this.signMultiIssuedVerifiableCredential.bind(this),
      createMultiIssuerVerifiableCredential:
        this.createMultiIssuerVerifiableCredential.bind(this),
      verifyMultisignatureCredential:
        this.verifyMultisignatureCredential.bind(this),
      aggregateBlsPublicKeys: this.aggregateBlsPublicKeys.bind(this),
      createProofOfOwnershipMultiIssuerVerifiableCredential:
        this.createProofOfOwnershipMultiIssuerVerifiableCredential.bind(this),
      verifyProofOfOwnershipMultisignatureCredential:
        this.verifyProofOfOwnershipMultisignatureCredential.bind(this),

      // VP helpers mirroring VC modus operandi
      signMultiHolderVerifiablePresentation:
        this.signMultiHolderVerifiablePresentation.bind(this),
      createMultiHolderVerifiablePresentation:
        this.createMultiHolderVerifiablePresentation.bind(this),
      createProofOfOwnershipMultiHolderVerifiablePresentation:
        this.createProofOfOwnershipMultiHolderVerifiablePresentation.bind(this),
      verifyMultisignaturePresentation:
        this.verifyMultisignaturePresentation.bind(this),
      verifyProofOfOwnershipMultisignaturePresentation:
        this.verifyProofOfOwnershipMultisignaturePresentation.bind(this),
    }
  }

  /**
   * Checks if a key is suitable for signing JWT payloads.
   * @param key - the key to check
   * @param context - the Veramo agent context, unused here
   *
   * @beta
   */
  async matchKeyForJWT(
    key: IKey,
    context: IssuerAgentContext,
  ): Promise<boolean> {
    return this.providers.some((provider) =>
      provider.getProofFormatsSupportedForKey(key).includes('jwt'),
    )
  }

  /**
   * Verifies a multisignature credential using the issuer list embedded in the document.
   *
   * @public
   */
  async verifyMultisignatureCredential(
    args: IVerifyMultisignatureCredentialArgs,
    context: VerifierAgentContext,
  ): Promise<IVerifyResult> {
    const { credential, policies, ...otherOptions } = args
    try {
      return await verifyCredentialMultiSignatureBls(
        credential,
        context,
        otherOptions?.resolutionOptions,
        this.blsBackend,
      )
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

  /**
   * Verifies a proof-of-ownership protected multisignature credential.
   *
   * @public
   */
  async verifyProofOfOwnershipMultisignatureCredential(
    args: IVerifyProofOfOwnershipMultisignatureCredentialArgs,
    context: VerifierAgentContext,
  ): Promise<IVerifyResult> {
    const { credential, policies, ...otherOptions } = args
    try {
      return await verifyCredentialProofOfOwnershipMultiSignatureBls(
        credential,
        context,
        otherOptions?.resolutionOptions,
        this.blsBackend,
      )
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

  /**
   * Aggregates multiple BLS public keys into a single public key.
   *
   * @public
   */
  async aggregateBlsPublicKeys(
    args: IAggregateBlsPublicKeysArgs,
    context: IssuerAgentContext,
  ): Promise<IAggregateBlsPublicKeysResult> {
    const bls_aggregated_pubkey = await new BlsCrypto(
      this.blsBackend,
    ).aggregatePublicKeys(args.list_of_publicKeyHex)
    return { bls_aggregated_pubkey }
  }

  /**
   * Collects a partial BLS signature for a multi-issuer credential payload.
   *
   * The issuer signs the canonicalized credential, the returned fragment carries both the payload it
   * signed and the signature, so the aggregator can check what was agreed upon.
   *
   * @public
   */
  async signMultiIssuedVerifiableCredential(
    args: ISignMultiIssuerVerifiableCredentialArgs,
    context: IssuerAgentContext,
  ): Promise<IMultisignatureSigningResult> {
    const {
      credential,
      issuer,
      proofFormat,
      keyRef,
      removeOriginalFields,
      save,
      now,
      ...otherOptions
    } = args
    const payload = withCredentialContextAndType(credential)

    //FIXME: if the identifier is not found, the error message should reflect that.
    if (!issuer || typeof issuer === 'undefined') {
      throw new Error('invalid_argument: credential.issuer must not be empty')
    }
    const identifier = await getManagedIssuer(issuer, context)

    if (!isPartialSignatureFormat(proofFormat)) {
      throw new Error(
        'invalid_argument: proofFormat must be "sign-bls-multi-signature" or any other supported proof format',
      )
    }
    const signer = wrapSigner(
      context,
      pickSigningKey(identifier, keyRef),
      PARTIAL_SIGNATURE_ALG,
    )
    return await signMultiSignatureVerifiableCredentialBls(
      payload,
      { did: identifier.did, signer, alg: PARTIAL_SIGNATURE_ALG },
      { ...otherOptions },
    )
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
    const {
      credential,
      issuer,
      proofFormat,
      keyRef,
      signatures,
      removeOriginalFields,
      save,
      now,
      ...otherOptions
    } = args
    const payload = withCredentialContextAndType(credential)

    const issuerDid = typeof issuer === 'string' ? issuer : issuer?.id
    if (!issuerDid || typeof issuerDid === 'undefined') {
      throw new Error('invalid_argument: credential.issuer must not be empty')
    }
    const identifier = await getManagedIssuer(issuerDid, context)

    if (
      (proofFormat as ExtendedProofFormat) !== 'aggregate-bls-multi-signature'
    ) {
      throw new Error(
        'invalid_argument: proofFormat must be "bls-multi-signature" or any other supported proof format',
      )
    }
    const signer = wrapSigner(
      context,
      pickSigningKey(identifier, keyRef),
      AGGREGATE_SIGNATURE_ALG,
    )
    const aggregated = await aggregateMultiSignatureVerifiableCredentialBls(
      payload,
      { did: identifier.did, signer, alg: AGGREGATE_SIGNATURE_ALG },
      signatures,
      { ...otherOptions },
    )
    return normalizeCredential(aggregated)
  }

  /**
   * Creates a proof-of-ownership protected multisignature credential.
   *
   * The BLS signatures are aggregated off-key here, so no managed identifier is needed; `proofData` and
   * `type` are accepted for caller convenience but the credential keeps its own fields.
   *
   * @public
   */
  async createProofOfOwnershipMultiIssuerVerifiableCredential(
    args: ICreateProofOfOwnershipMultiIssuerVerifiableCredentialArgs,
    context: IssuerAgentContext,
  ): Promise<VerifiableCredential> {
    const {
      credential,
      proofData,
      type,
      proofsOfOwnership,
      proofFormat,
      signatures,
      removeOriginalFields,
      save,
      now,
      ...otherOptions
    } = args
    const payload = withCredentialContextAndType(credential)

    if (
      (proofFormat as ExtendedProofFormat) !==
      'ProofOfOwnership-aggregate-bls-multi-signature'
    ) {
      throw new Error(
        'invalid_argument: proofFormat must be "bls-multi-signature" or any other supported proof format',
      )
    }
    return await generateProofOfOwnershipMultiIssuerVerifiableCredentialBls(
      payload,
      proofsOfOwnership,
      signatures,
      undefined,
      this.blsBackend,
    )
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
    const payload = withPresentationContextAndType(presentation)

    const identifier = await context.agent.didManagerGet({ did: holder })
    const signer = wrapSigner(
      context,
      pickSigningKey(identifier, keyRef),
      PARTIAL_SIGNATURE_ALG,
    )

    // returns { signatureData: { payloadToSign, signatureHex } }
    return await signMultiSignatureVerifiablePresentationBls(
      payload,
      { did: identifier.did, signer, alg: PARTIAL_SIGNATURE_ALG },
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
    const payload = withPresentationContextAndType(presentation)

    // coordinator DID/key to perform aggregation signing
    const managed = (await context.agent.didManagerFind())[0]
    if (!managed) throw new Error('no_managed_did: required for aggregation')
    const signer = wrapSigner(
      context,
      pickAggregationKey(managed, keyRef),
      AGGREGATE_SIGNATURE_ALG,
    )

    const vp = await aggregateMultiSignatureVerifiablePresentationBls(
      payload,
      { did: managed.did, signer, alg: AGGREGATE_SIGNATURE_ALG },
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
    const payload = withPresentationContextAndType(presentation)

    const vp =
      await generateProofOfOwnershipMultiIssuerVerifiablePresentationBls(
        payload,
        proofsOfOwnership,
        signatures,
        undefined,
        this.blsBackend,
      )
    return vp
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

/** The proof formats under which an issuer or a holder contributes its own partial BLS signature. */
function isPartialSignatureFormat(proofFormat: ProofFormat): boolean {
  const format = proofFormat as ExtendedProofFormat
  return (
    format === 'sign-bls-multi-signature' ||
    format === 'sign-bls-multi-signature-vp' ||
    format === 'aggregate-bls-multi-signature-vp' ||
    format === 'ProofOfOwnership-aggregate-bls-multi-signature-vp'
  )
}

/** The issuer must be a DID managed by this agent, its key produces the partial or aggregated signature. */
async function getManagedIssuer(
  did: string,
  context: IssuerAgentContext,
): Promise<IIdentifier> {
  try {
    return await context.agent.didManagerGet({ did })
  } catch (e) {
    throw new Error(
      `invalid_argument: credential.issuer must be a DID managed by this agent. ${e}`,
    )
  }
}

/** The coordinator aggregates with its BLS key, unless the caller points at another one. */
function pickAggregationKey(identifier: IIdentifier, keyRef?: string): IKey {
  if (keyRef) return pickSigningKey(identifier, keyRef)

  const blsKey = identifier.keys.find((k) => k.type === 'Bls12381G1')
  if (!blsKey) {
    throw new Error(
      `key_not_found: No Bls12381G1 key for aggregation on ${identifier.did}`,
    )
  }
  return blsKey
}
