import assert from 'node:assert/strict'
import { it } from 'node:test'
import { CredentialPlugin as W3cCredentialPlugin } from '@veramo/credential-w3c'
import { CredentialProviderEIP712 } from '@veramo/credential-eip712'
import {
  CredentialPlugin,
  CredentialProviderBls,
} from '@veramo-community/credential-w3c-bls-multisig'
import {
  createFixture,
  createMultisignature,
  credentialPayload,
} from './fixtures.js'
import type { ProofOfOwnershipMultiIssuerVerifiableCredential } from '@veramo-community/credential-w3c-bls-multisig'

it('registers the BLS provider directly with the official Veramo 7 plugin', async () => {
  const credentialPlugin = new W3cCredentialPlugin([
    new CredentialProviderBls(),
  ])
  const { agent, actors } = await createFixture('chainsafe', {
    credentialPlugin,
    schemaValidation: true,
  })
  const credential = await agent.createVerifiableCredential({
    credential: credentialPayload(actors[0], actors[2]),
    proofFormat: 'bls',
  })
  assert.equal((await agent.verifyCredential({ credential })).verified, true)
})

it('accepts the official EIP-712 provider through plugin options', async () => {
  const credentialPlugin = new CredentialPlugin({
    providers: [new CredentialProviderEIP712()],
  })
  const { agent, actors } = await createFixture('chainsafe', {
    credentialPlugin,
    schemaValidation: true,
  })
  const credential = await agent.createVerifiableCredential({
    credential: credentialPayload(actors[0], actors[2]),
    proofFormat: 'EthereumEip712Signature2021',
  })
  assert.equal((await agent.verifyCredential({ credential })).verified, true)
})

it('runs custom multisignature methods with agent schema validation enabled', async () => {
  const fixture = await createFixture('noble', { schemaValidation: true })
  const credential = (await createMultisignature(
    fixture,
  )) as ProofOfOwnershipMultiIssuerVerifiableCredential
  assert.equal(
    (
      await fixture.agent.verifyProofOfOwnershipMultisignatureCredential({
        credential,
      })
    ).verified,
    true,
  )
})
