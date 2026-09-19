# @veramo-community/kms-local-bls

BLS key management for Veramo 7.0.1. `BlsKeyManagementSystem` extends Veramo's maintained `KeyManagementSystem`; standard key operations use the upstream implementation.

```typescript
import { BlsKeyManagementSystem } from '@veramo-community/kms-local-bls'
import { MemoryPrivateKeyStore } from '@veramo/key-manager'

const kms = new BlsKeyManagementSystem(new MemoryPrivateKeyStore(), {
  blsBackend: 'chainsafe',
})
```

Register the KMS with Veramo's `KeyManager`. It supports `Bls12381G1` keys, `BLS_SIGNATURE`, and `BLS_AGGREGATE_MULTI_SIGNATURE`, alongside the standard local KMS algorithms.

The backend is `chainsafe` by default, or `noble`. `VERAMO_BLS_BACKEND` supplies the default when no constructor option is given. Use the same backend for signing and verification; the existing backend-specific signing conventions are retained.

The package also exports `SecretBox` and the shared `BlsCrypto` byte operations used by the credential plugin. Build from the repository root with `corepack yarn build`.
