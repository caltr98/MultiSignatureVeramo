/**
 * Provides a {@link @veramo/credential-w3c#CredentialPlugin | plugin} for the {@link @veramo/core#Agent} that
 * implements
 * {@link @veramo/core-types#ICredentialIssuer} interface, extended with the BLS multi-signature operations.
 *
 * Standard proof formats are handled by the official Veramo credential providers; the BLS ones by
 * {@link CredentialProviderBls} and by the custom methods of {@link CredentialPlugin}.
 *
 * Provides a {@link @veramo/credential-w3c#W3cMessageHandler | plugin} for the
 * {@link @veramo/message-handler#MessageHandler} that verifies Credentials and Presentations in a message.
 *
 * @packageDocumentation
 */
export { W3cMessageHandler, MessageTypes } from './message-handler.js'
import { CredentialPlugin } from './action-handler.js'

/**
 * @deprecated please use {@link CredentialPlugin} instead
 * @public
 */
const CredentialIssuer = CredentialPlugin
export { CredentialIssuer, CredentialPlugin }

export { CredentialProviderBls } from './bls-credential-provider.js'
export type { BlsBackend } from './bls-credential-provider.js'

export type {
  ICustomCredentialPlugin,
  MultiIssuerVerifiableCredential,
  MultiIssuerVerifiablePresentation,
  ProofOfOwnershipMultiIssuerVerifiableCredential,
  ProofOfOwnershipMultiIssuerVerifiablePresentation,
  IAggregateBlsPublicKeysArgs,
  IAggregateBlsPublicKeysResult,
  IMultisignatureFragment,
  IMultisignatureSigningResult,
  ISignMultiIssuerVerifiableCredentialArgs,
  ICreateMultiIssuerVerifiableCredentialArgs,
  ICreateProofOfOwnershipMultiIssuerVerifiableCredentialArgs,
  IVerifyMultisignatureCredentialArgs,
  IVerifyProofOfOwnershipMultisignatureCredentialArgs,
  ISignMultiHolderVerifiablePresentationArgs,
  ICreateMultiHolderVerifiablePresentationArgs,
  ICreateProofOfOwnershipMultiHolderVerifiablePresentationArgs,
  IVerifyMultisignaturePresentationArgs,
  IVerifyProofOfOwnershipMultisignaturePresentationArgs,
} from './action-handler.js'

// For backward compatibility, re-export the plugin types that were moved to core in v4
export type { ICredentialIssuer, ICredentialVerifier } from '@veramo/core-types'

// The provider contract an agent can implement to add another proof format to this plugin
export type {
  ICredentialProvider,
  ProofFormatQuery,
  TentativeVerificationQuery,
} from '@veramo/credential-w3c'
