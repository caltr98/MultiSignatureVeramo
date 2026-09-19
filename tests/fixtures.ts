import { createAgent } from '@veramo/core'
import type {
  IAgentPlugin,
  ICredentialPlugin,
  IDIDManager,
  IKeyManager,
  IResolver,
  IIdentifier,
  PresentationPayload,
} from '@veramo/core-types'
import {
  KeyManager,
  MemoryKeyStore,
  MemoryPrivateKeyStore,
} from '@veramo/key-manager'
import { MemoryDIDStore } from '@veramo/did-manager'
import type { DIDDocument } from 'did-resolver'
import { computeAddress } from 'ethers'
import {
  BlsKeyManagementSystem,
  type BlsBackend,
} from '@veramo-community/kms-local-bls'
import { DIDManagerBls } from '@veramo-community/did-manager-bls'
import {
  CredentialPlugin,
  type ICustomCredentialPlugin,
} from '@veramo-community/credential-w3c-bls-multisig'
import type {
  MultiIssuerVerifiableCredential,
  MultiIssuerVerifiablePresentation,
} from '@veramo-community/credential-w3c-bls-multisig'

export async function createFixture(
  backend: BlsBackend,
  options: { credentialPlugin?: IAgentPlugin; schemaValidation?: boolean } = {},
) {
  const documents = new Map<string, DIDDocument>()
  const resolutions: string[] = []
  const didStore = new MemoryDIDStore()
  const agent = createAgent<
    ICredentialPlugin &
      ICustomCredentialPlugin &
      IDIDManager &
      IKeyManager &
      IResolver
  >({
    schemaValidation: options.schemaValidation,
    plugins: [
      new KeyManager({
        store: new MemoryKeyStore(),
        kms: {
          local: new BlsKeyManagementSystem(new MemoryPrivateKeyStore(), {
            blsBackend: backend,
          }),
        },
      }),
      new DIDManagerBls({
        store: didStore,
        defaultProvider: 'did:ethr:sepolia',
        providers: {},
      }),
      options.credentialPlugin ?? new CredentialPlugin({ blsBackend: backend }),
      {
        methods: {
          resolveDid: async ({ didUrl }: { didUrl: string }) => {
            resolutions.push(didUrl)
            const didDocument = documents.get(didUrl.split('#')[0]) ?? null
            return {
              didDocument,
              didDocumentMetadata: {},
              didResolutionMetadata: didDocument ? {} : { error: 'notFound' },
            }
          },
        },
      },
    ],
  })

  async function createActor(): Promise<IIdentifier> {
    const controller = await agent.keyManagerCreate({
      kms: 'local',
      type: 'Secp256k1',
    })
    const bls = await agent.keyManagerCreate({
      kms: 'local',
      type: 'Bls12381G1',
    })
    const did = `did:ethr:sepolia:${computeAddress(`0x${controller.publicKeyHex}`)}`
    documents.set(
      did,
      didDocument(did, controller.publicKeyHex, bls.publicKeyHex),
    )
    const identifier = {
      did,
      provider: 'did:ethr:sepolia',
      controllerKeyId: controller.kid,
      keys: [controller, bls],
      services: [],
    }
    await didStore.importDID(identifier)
    return identifier
  }

  return {
    agent,
    documents,
    resolutions,
    actors: await Promise.all([createActor(), createActor(), createActor()]),
  }
}

function didDocument(
  did: string,
  controllerKey: string,
  blsKey: string,
): DIDDocument {
  return {
    id: did,
    '@context': 'https://www.w3.org/ns/did/v1',
    verificationMethod: [
      {
        id: `${did}#controller`,
        controller: did,
        type: 'EcdsaSecp256k1RecoveryMethod2020',
        publicKeyHex: controllerKey,
        blockchainAccountId: `eip155:11155111:${computeAddress(`0x${controllerKey}`)}`,
      },
      {
        id: `${did}#delegate-1`,
        controller: did,
        type: 'Bls12381G1',
        publicKeyHex: blsKey,
      },
    ],
    authentication: [`${did}#controller`, `${did}#delegate-1`],
    assertionMethod: [`${did}#controller`, `${did}#delegate-1`],
  }
}

export function credentialPayload(issuer: IIdentifier, holder: IIdentifier) {
  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential'],
    issuer: issuer.did,
    issuanceDate: '2020-01-01T00:00:00.000Z',
    credentialSubject: { id: holder.did, name: 'Alice' },
  }
}

export type Fixture = Awaited<ReturnType<typeof createFixture>>

export async function createMultisignature(
  fixture: Fixture,
  presentation = false,
  ownership = true,
) {
  const { agent, actors } = fixture
  const signers = actors.slice(0, 2)
  const keys = signers.map(
    (actor) => actor.keys.find((key) => key.type === 'Bls12381G1')!,
  )
  const { bls_aggregated_pubkey } = await agent.aggregateBlsPublicKeys({
    list_of_publicKeyHex: keys.map((key) => key.publicKeyHex),
  })
  const payload = presentation
    ? {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiablePresentation'],
        holder: signers[0].did,
        multi_holders: signers.map((actor) => actor.did),
        verifiableCredential: [],
        aggregated_bls_public_key: bls_aggregated_pubkey,
        attributes: { purpose: 'test' },
      }
    : {
        ...credentialPayload(signers[0], actors[2]),
        multi_issuers: signers.map((actor) => actor.did),
        aggregated_bls_public_key: bls_aggregated_pubkey,
      }
  const partials = await Promise.all(
    signers.map((actor, index) =>
      presentation
        ? agent.signMultiHolderVerifiablePresentation({
            presentation: payload as PresentationPayload,
            holder: actor.did,
            keyRef: keys[index].kid,
            proofFormat: 'sign-bls-multi-signature-vp',
          })
        : agent.signMultiIssuedVerifiableCredential({
            credential: payload,
            issuer: actor.did,
            keyRef: keys[index].kid,
            proofFormat: 'sign-bls-multi-signature',
          }),
    ),
  )
  const signatures = partials.map(
    (partial) => partial.signatureData.signatureHex,
  )
  const canonical = partials[0].signatureData.payloadToSign
  const proofsOfOwnership = await Promise.all(
    signers.map((actor) =>
      agent.keyManagerSign({
        keyRef: actor.controllerKeyId!,
        data: presentation ? canonical : JSON.stringify(canonical),
        algorithm: 'eth_signMessage',
        encoding: 'utf-8',
      }),
    ),
  )
  if (presentation)
    return (await (ownership
      ? agent.createProofOfOwnershipMultiHolderVerifiablePresentation({
          presentation: payload as PresentationPayload,
          signatures,
          proofsOfOwnership,
          proofFormat: 'ProofOfOwnership-aggregate-bls-multi-signature-vp',
        })
      : agent.createMultiHolderVerifiablePresentation({
          presentation: payload as PresentationPayload,
          signatures,
          keyRef: keys[0].kid,
          proofFormat: 'aggregate-bls-multi-signature-vp',
        }))) as unknown as MultiIssuerVerifiablePresentation
  return (await (ownership
    ? agent.createProofOfOwnershipMultiIssuerVerifiableCredential({
        credential: payload,
        signatures,
        proofsOfOwnership,
        proofFormat: 'ProofOfOwnership-aggregate-bls-multi-signature',
      })
    : agent.createMultiIssuerVerifiableCredential({
        credential: payload,
        issuer: signers[0].did,
        signatures,
        keyRef: keys[0].kid,
        proofFormat: 'aggregate-bls-multi-signature',
      }))) as unknown as MultiIssuerVerifiableCredential
}
