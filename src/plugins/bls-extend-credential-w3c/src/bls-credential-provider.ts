// BLS proof format plugged into the official Veramo 7 credential pipeline.
//
// Only the single signature flow ('bls' proof format) fits the provider contract: issuing needs one
// key and verification needs one document. The multisignature flows (partial signatures, aggregation,
// proofs of ownership) need several rounds between issuers, so they stay as custom methods on
// {@link CredentialPlugin}.

import {
  CredentialPayload,
  ICreateVerifiableCredentialArgs,
  ICreateVerifiablePresentationArgs,
  IIdentifier,
  IKey,
  IssuerAgentContext,
  IVerifyCredentialArgs,
  IVerifyPresentationArgs,
  IVerifyResult,
  PresentationPayload,
  ProofFormat,
  VerifiableCredential,
  VerifiablePresentation,
  VerifierAgentContext,
} from '@veramo/core-types'
import type {
  ICredentialProvider,
  ProofFormatQuery,
  TentativeVerificationQuery,
} from '@veramo/credential-w3c'
import {
  extractIssuer,
  isDefined,
  MANDATORY_CREDENTIAL_CONTEXT,
  processEntryToArray,
  removeDIDParameters,
} from '@veramo/utils'
import { normalizeCredential, normalizePresentation } from 'did-jwt-vc'

import {
  createVerifiableCredentialBls,
  verifyCredentialBls,
} from './bls-credentials.js'
import {
  createVerifiablePresentationBls,
  verifyPresentationBls,
} from './bls-presentations.js'
import { pickSigningKey, wrapSigner } from './signing-keys.js'

import {
  resolveBlsBackend,
  type BlsBackend,
} from '@veramo-community/kms-local-bls'
export type { BlsBackend }

/** The KMS exposes the single BLS signature under this algorithm name. */
const BLS_SIGNATURE_ALG = 'BLS_SIGNATURE'

// Aggregate proofs use the dedicated multisignature methods on CredentialPlugin.
const BLS_PROOF_TYPES = ['BlsSignaturePisa']

/**
 * Issues and verifies BLS signed Verifiable Credentials and Presentations.
 *
 * @public
 */
export class CredentialProviderBls implements ICredentialProvider {
  private readonly blsBackend: BlsBackend

  constructor(options: { blsBackend?: BlsBackend } = {}) {
    this.blsBackend = resolveBlsBackend(options.blsBackend)
  }

  /** {@inheritdoc @veramo/credential-w3c#ICredentialProvider.getProofFormatsSupportedForKey} */
  getProofFormatsSupportedForKey(key: IKey): ProofFormat[] {
    return key.type === 'Bls12381G1' ? ['bls'] : []
  }

  /** {@inheritdoc @veramo/credential-w3c#ICredentialProvider.canIssueProofFormat} */
  canIssueProofFormat(query: ProofFormatQuery): boolean {
    return query.proofFormat === 'bls'
  }

  /** {@inheritdoc @veramo/credential-w3c#ICredentialProvider.canVerifyDocumentType} */
  canVerifyDocumentType(query: TentativeVerificationQuery): boolean {
    const proofType = (<VerifiableCredential>query.document)?.proof?.type
    return typeof proofType === 'string' && BLS_PROOF_TYPES.includes(proofType)
  }

  /** {@inheritdoc @veramo/core-types#ICredentialIssuer.createVerifiableCredential} */
  async createVerifiableCredential(
    args: ICreateVerifiableCredentialArgs,
    context: IssuerAgentContext,
  ): Promise<VerifiableCredential> {
    const payload = withCredentialContextAndType({
      issuanceDate: issuanceDate(args.now),
      ...args.credential,
    })
    const identifier = await getCredentialIssuer(payload, context)
    const signer = wrapSigner(
      context,
      pickSigningKey(identifier, args.keyRef),
      BLS_SIGNATURE_ALG,
    )
    const signed = await createVerifiableCredentialBls(
      payload,
      { did: identifier.did, signer, alg: BLS_SIGNATURE_ALG },
      args,
    )
    return normalizeCredential(signed)
  }

  /** {@inheritdoc @veramo/core-types#ICredentialVerifier.verifyCredential} */
  async verifyCredential(
    args: IVerifyCredentialArgs,
    context: VerifierAgentContext,
  ): Promise<IVerifyResult> {
    const credential = <VerifiableCredential>args.credential
    return await verifyCredentialBls(
      credential,
      context,
      args.resolutionOptions,
      this.blsBackend,
    )
  }

  /** {@inheritdoc @veramo/core-types#ICredentialIssuer.createVerifiablePresentation} */
  async createVerifiablePresentation(
    args: ICreateVerifiablePresentationArgs,
    context: IssuerAgentContext,
  ): Promise<VerifiablePresentation> {
    const payload = presentationToSign(args)
    const identifier = await getPresentationHolder(payload.holder, context)
    const signer = wrapSigner(
      context,
      pickSigningKey(identifier, args.keyRef),
      BLS_SIGNATURE_ALG,
    )
    const signed = await createVerifiablePresentationBls(
      payload,
      { did: identifier.did, signer, alg: BLS_SIGNATURE_ALG },
      args,
    )
    return normalizePresentation(signed)
  }

  /** {@inheritdoc @veramo/core-types#ICredentialVerifier.verifyPresentation} */
  async verifyPresentation(
    args: IVerifyPresentationArgs,
    context: VerifierAgentContext,
  ): Promise<IVerifyResult> {
    const presentation = <VerifiablePresentation>args.presentation
    if (!matchesPresentationRequest(presentation, args)) {
      return {
        verified: false,
        error: {
          errorCode: 'invalid_presentation',
          message: 'Presentation challenge or domain does not match',
        },
      }
    }
    return await verifyPresentationBls(
      presentation,
      context,
      args.resolutionOptions,
      this.blsBackend,
    )
  }
}

/**
 * Credentials always travel with the mandatory context and the `VerifiableCredential` type.
 *
 * @public
 */
export function withCredentialContextAndType(
  credential: CredentialPayload,
): CredentialPayload {
  return {
    ...credential,
    '@context': processEntryToArray(
      credential['@context'],
      MANDATORY_CREDENTIAL_CONTEXT,
    ),
    type: processEntryToArray(credential.type, 'VerifiableCredential'),
  }
}

/**
 * Presentations always travel with the mandatory context and the `VerifiablePresentation` type.
 *
 * @public
 */
export function withPresentationContextAndType(
  presentation: PresentationPayload,
): PresentationPayload {
  return {
    ...presentation,
    '@context': processEntryToArray(
      presentation['@context'],
      MANDATORY_CREDENTIAL_CONTEXT,
    ),
    type: processEntryToArray(presentation.type, 'VerifiablePresentation'),
  }
}

/** `now` is expressed in seconds when it is a number, like in the standard Veramo flows. */
function issuanceDate(now?: number | Date): string {
  const issuedAt = typeof now === 'number' ? new Date(now * 1000) : now
  return (issuedAt instanceof Date ? issuedAt : new Date()).toISOString()
}

// Embedded credentials keep their original representation for canonicalization.
function presentationToSign(
  args: ICreateVerifiablePresentationArgs,
): PresentationPayload {
  return withPresentationContextAndType({
    issuanceDate: issuanceDate(args.now),
    ...args.presentation,
    ...(args.challenge !== undefined && { challenge: args.challenge }),
    ...(args.domain !== undefined && { domain: args.domain }),
  })
}

function matchesPresentationRequest(
  presentation: VerifiablePresentation,
  args: IVerifyPresentationArgs,
): boolean {
  return (
    (args.challenge === undefined ||
      presentation.challenge === args.challenge) &&
    (args.domain === undefined || presentation.domain === args.domain)
  )
}

/** The issuer must be a DID managed by this agent, we sign with one of its keys. */
async function getCredentialIssuer(
  credential: CredentialPayload,
  context: IssuerAgentContext,
): Promise<IIdentifier> {
  //FIXME: if the identifier is not found, the error message should reflect that.
  const issuer = extractIssuer(credential, { removeParameters: true })
  if (!issuer || typeof issuer === 'undefined') {
    throw new Error('invalid_argument: credential.issuer must not be empty')
  }
  try {
    return await context.agent.didManagerGet({ did: issuer })
  } catch (e) {
    throw new Error(
      `invalid_argument: credential.issuer must be a DID managed by this agent. ${e}`,
    )
  }
}

/** Same for the holder of a presentation. */
async function getPresentationHolder(
  holder: string | undefined,
  context: IssuerAgentContext,
): Promise<IIdentifier> {
  if (!isDefined(holder)) {
    throw new Error('invalid_argument: presentation.holder must not be empty')
  }
  try {
    return await context.agent.didManagerGet({
      did: removeDIDParameters(holder),
    })
  } catch (e) {
    throw new Error(
      'invalid_argument: presentation.holder must be a DID managed by this agent',
    )
  }
}
