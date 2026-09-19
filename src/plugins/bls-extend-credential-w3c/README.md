# @veramo-community/credential-w3c-bls-multisig

Veramo 7.0.1 credential plugin for single BLS signatures, multi-issuer credentials, and multi-holder presentations.

## Agent setup

The custom plugin includes the official JWT provider and the BLS provider:

```typescript
import { CredentialPlugin } from '@veramo-community/credential-w3c-bls-multisig'
import { CredentialProviderEIP712 } from '@veramo/credential-eip712'

const credentials = new CredentialPlugin({
  blsBackend: 'chainsafe',
  providers: [new CredentialProviderEIP712()],
})
```

Register `credentials` in the agent's `plugins` array alongside key management, DID management, and resolution. BLS signing needs `BlsKeyManagementSystem` from `@veramo-community/kms-local-bls`. Use the same BLS backend for the KMS and credential plugin.

Veramo 7 uses credential providers. Additional formats such as EIP-712 or linked-data proofs belong in `providers`. The old `CredentialIssuer` export remains an alias for `CredentialPlugin`.

## Methods

Single signatures use the standard creation and verification methods with `proofFormat: 'bls'`. An explicit `keyRef` selects the BLS key; otherwise the provider selects the first managed BLS key. BLS presentations sign any supplied `challenge` and `domain`, which verification checks when expected values are provided.

The existing custom methods remain available:

- VC: `signMultiIssuedVerifiableCredential`, `createMultiIssuerVerifiableCredential`, `createProofOfOwnershipMultiIssuerVerifiableCredential`.
- VP: `signMultiHolderVerifiablePresentation`, `createMultiHolderVerifiablePresentation`, `createProofOfOwnershipMultiHolderVerifiablePresentation`.
- Verification: `verifyMultisignatureCredential`, `verifyMultisignaturePresentation`, `verifyProofOfOwnershipMultisignatureCredential`, `verifyProofOfOwnershipMultisignaturePresentation`.
- Key aggregation: `aggregateBlsPublicKeys`.

Use the corresponding custom verification method for an aggregate proof. It checks the signed payload, ordered signer roster, and ownership proofs where applicable. Application trust, credential-status, and time policies remain the caller's responsibility. The existing proof names and VC/VP ownership-message encodings are retained.

`CredentialProviderBls` can also be registered directly with the official `CredentialPlugin` from `@veramo/credential-w3c` when only single BLS signatures are needed. `W3cMessageHandler`, `MessageTypes`, and the custom argument/result types remain exported.

## Build and test

From the repository root:

```bash
corepack yarn install --frozen-lockfile
corepack yarn build
corepack yarn test
```

Package output is generated in `build/`. The regression tests exercise the public package exports with real signatures and in-memory DID documents.
