import assert from 'node:assert/strict'
import { before, describe, it } from 'node:test'
import {
  BlsCrypto,
  BlsKeyManagementSystem,
} from '@veramo-community/kms-local-bls'
import { MemoryPrivateKeyStore } from '@veramo/key-manager'
import type {
  VerifiableCredential,
  VerifiablePresentation,
} from '@veramo/core-types'
import type {
  MultiIssuerVerifiableCredential,
  MultiIssuerVerifiablePresentation,
  ProofOfOwnershipMultiIssuerVerifiableCredential,
  ProofOfOwnershipMultiIssuerVerifiablePresentation,
} from '../src/plugins/bls-extend-credential-w3c/src/action-handler.js'
import {
  createFixture,
  createMultisignature,
  credentialPayload,
  type Fixture,
} from './fixtures.js'

for (const backend of ['chainsafe', 'noble'] as const) {
  describe(`${backend}: Veramo 7 credential integration`, () => {
    let fixture: Fixture
    let credential: VerifiableCredential
    let multi: ProofOfOwnershipMultiIssuerVerifiableCredential
    let presentation: ProofOfOwnershipMultiIssuerVerifiablePresentation

    before(async () => {
      fixture = await createFixture(backend)
      credential = await fixture.agent.createVerifiableCredential({
        credential: credentialPayload(fixture.actors[0], fixture.actors[2]),
        proofFormat: 'bls',
        keyRef: fixture.actors[0].keys[1].kid,
      })
      multi = (await createMultisignature(
        fixture,
      )) as ProofOfOwnershipMultiIssuerVerifiableCredential
      presentation = (await createMultisignature(
        fixture,
        true,
      )) as ProofOfOwnershipMultiIssuerVerifiablePresentation
    })

    it('round-trips a dated single-issuer BLS credential', async () => {
      assert.equal(
        (await fixture.agent.verifyCredential({ credential })).verified,
        true,
      )
    })

    it('rejects a changed issuance date and subject', async () => {
      for (const changes of [
        { issuanceDate: '2021-01-01T00:00:00.000Z' },
        { credentialSubject: { name: 'Mallory' } },
      ]) {
        assert.equal(
          (
            await fixture.agent.verifyCredential({
              credential: { ...credential, ...changes },
            })
          ).verified,
          false,
        )
      }
    })

    it('requires the exact verification method referenced by the proof', async () => {
      const modified = structuredClone(credential)
      modified.proof.verificationMethod = `${fixture.actors[0].did}#missing-key`
      assert.equal(
        (await fixture.agent.verifyCredential({ credential: modified }))
          .verified,
        false,
      )
    })

    it('returns a failed verification result for malformed signature bytes', async () => {
      const modified = structuredClone(credential)
      modified.proof.signatureValue = 'not-hex'
      assert.equal(
        (await fixture.agent.verifyCredential({ credential: modified }))
          .verified,
        false,
      )
    })

    it('keeps standard JWT credential and presentation issuance working', async () => {
      const vc = await fixture.agent.createVerifiableCredential({
        credential: credentialPayload(fixture.actors[0], fixture.actors[2]),
        proofFormat: 'jwt',
      })
      assert.equal(
        (await fixture.agent.verifyCredential({ credential: vc })).verified,
        true,
      )
      const vp = await fixture.agent.createVerifiablePresentation({
        presentation: {
          holder: fixture.actors[2].did,
          verifiableCredential: [vc],
        },
        proofFormat: 'jwt',
        challenge: 'fresh-nonce',
      })
      assert.equal(
        (
          await fixture.agent.verifyPresentation({
            presentation: vp,
            challenge: 'fresh-nonce',
          })
        ).verified,
        true,
      )
    })

    it('round-trips a BLS presentation and preserves signed attributes', async () => {
      const vp = await fixture.agent.createVerifiablePresentation({
        presentation: {
          holder: fixture.actors[2].did,
          verifiableCredential: [],
          attributes: { purpose: 'test' },
          issuanceDate: '2020-01-01T00:00:00.000Z',
        },
        proofFormat: 'bls',
        keyRef: fixture.actors[2].keys[1].kid,
      })
      assert.deepEqual(vp.attributes, { purpose: 'test' })
      assert.equal(
        (await fixture.agent.verifyPresentation({ presentation: vp })).verified,
        true,
      )
      assert.equal(
        (
          await fixture.agent.verifyPresentation({
            presentation: { ...vp, attributes: { purpose: 'changed' } },
          })
        ).verified,
        false,
      )
    })

    it('binds BLS presentations to the requested challenge and domain', async () => {
      const vp = await fixture.agent.createVerifiablePresentation({
        presentation: {
          holder: fixture.actors[2].did,
          verifiableCredential: [],
        },
        proofFormat: 'bls',
        challenge: 'nonce',
        domain: 'verifier.example',
      })
      assert.equal(
        (
          await fixture.agent.verifyPresentation({
            presentation: vp,
            challenge: 'nonce',
            domain: 'verifier.example',
          })
        ).verified,
        true,
      )
      assert.equal(
        (
          await fixture.agent.verifyPresentation({
            presentation: vp,
            challenge: 'different',
          })
        ).verified,
        false,
      )
      assert.equal(
        (
          await fixture.agent.verifyPresentation({
            presentation: vp,
            domain: 'another.example',
          })
        ).verified,
        false,
      )
      assert.equal(
        (
          await fixture.agent.verifyPresentation({
            presentation: { ...vp, challenge: 'different' },
            challenge: 'different',
          })
        ).verified,
        false,
      )
    })

    it('verifies a multi-issuer credential and a multi-holder presentation with ownership proofs', async () => {
      assert.equal(
        (
          await fixture.agent.verifyProofOfOwnershipMultisignatureCredential({
            credential: multi,
          })
        ).verified,
        true,
      )
      assert.equal(
        (
          await fixture.agent.verifyProofOfOwnershipMultisignaturePresentation({
            presentation,
          })
        ).verified,
        true,
      )
    })

    it('verifies aggregate credentials and presentations without ownership proofs', async () => {
      const vc = (await createMultisignature(
        fixture,
        false,
        false,
      )) as MultiIssuerVerifiableCredential
      const vp = (await createMultisignature(
        fixture,
        true,
        false,
      )) as MultiIssuerVerifiablePresentation
      assert.equal(
        (await fixture.agent.verifyMultisignatureCredential({ credential: vc }))
          .verified,
        true,
      )
      assert.equal(
        (
          await fixture.agent.verifyMultisignaturePresentation({
            presentation: vp,
          })
        ).verified,
        true,
      )
    })

    it('rejects a modified aggregate payload before resolving issuer DIDs', async () => {
      fixture.resolutions.length = 0
      const modified = { ...multi, credentialSubject: { name: 'Mallory' } }
      assert.equal(
        (
          await fixture.agent.verifyProofOfOwnershipMultisignatureCredential({
            credential: modified,
          })
        ).verified,
        false,
      )
      assert.equal(fixture.resolutions.length, 0)
    })

    it('rejects empty, missing, reordered, and malformed verification rosters', async () => {
      for (const methods of [
        [],
        [fixture.actors[0].did],
        [...multi.multi_issuers].reverse(),
        fixture.actors[0].did,
      ]) {
        const modified = structuredClone(multi)
        modified.proof.verificationMethod = methods
        assert.equal(
          (
            await fixture.agent.verifyProofOfOwnershipMultisignatureCredential({
              credential: modified,
            })
          ).verified,
          false,
        )
      }
    })

    it('rejects missing, reordered, and stale ownership signatures', async () => {
      for (const signatures of [
        multi.proof.ProofsOfOwnership.slice(0, 1),
        [...multi.proof.ProofsOfOwnership].reverse(),
        ['0x00', '0x00'],
      ]) {
        const modified = structuredClone(multi)
        modified.proof.ProofsOfOwnership = signatures
        assert.equal(
          (
            await fixture.agent.verifyProofOfOwnershipMultisignatureCredential({
              credential: modified,
            })
          ).verified,
          false,
        )
      }
    })

    it('fails when a DID no longer resolves to its ownership key', async () => {
      const did = multi.multi_issuers[0]
      const document = fixture.documents.get(did)!
      fixture.documents.delete(did)
      try {
        assert.equal(
          (
            await fixture.agent.verifyProofOfOwnershipMultisignatureCredential({
              credential: multi,
            })
          ).verified,
          false,
        )
      } finally {
        fixture.documents.set(did, document)
      }
    })

    it('rejects empty aggregation and missing partial signatures', async () => {
      await assert.rejects(() => new BlsCrypto(backend).aggregatePublicKeys([]))
      await assert.rejects(() =>
        fixture.agent.createProofOfOwnershipMultiIssuerVerifiableCredential({
          credential: multi as unknown as VerifiableCredential,
          signatures: [],
          proofsOfOwnership: multi.proof.ProofsOfOwnership,
          proofFormat: 'ProofOfOwnership-aggregate-bls-multi-signature',
        }),
      )
    })

    it('lists, signs with, and deletes BLS keys alongside standard keys', async () => {
      const kms = new BlsKeyManagementSystem(new MemoryPrivateKeyStore(), {
        blsBackend: backend,
      })
      const keys = await Promise.all([
        kms.createKey({ type: 'Bls12381G1' }),
        kms.createKey({ type: 'Secp256k1' }),
      ])
      assert.equal((await kms.listKeys()).length, 2)
      await kms.deleteKey({ kid: keys[0].kid })
      assert.equal((await kms.listKeys()).length, 1)
      await assert.rejects(() =>
        kms.sign({
          keyRef: keys[0],
          algorithm: 'BLS_SIGNATURE',
          data: new Uint8Array([1]),
        }),
      )
    })
  })
}

it('rejects an unknown backend instead of silently choosing another one', () => {
  assert.throws(
    () => new BlsCrypto('invalid' as 'chainsafe'),
    /Unsupported BLS backend/,
  )
})
