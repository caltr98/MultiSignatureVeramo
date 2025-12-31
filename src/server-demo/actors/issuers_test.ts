import { agent } from '../../veramo/setup.js'

/**
 * Create a Verifiable Credential for a given issuer/holder (JWT VC).
 */
export async function createVC(
  issuerDid: string,
  holderDid: string,
  attributes?: Record<string, any>,
) {
  const payload = generateVCPayload(holderDid, attributes)

  const vc = await agent.createVerifiableCredential({
    credential: {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential'],
      issuer: { id: issuerDid },
      issuanceDate: new Date().toISOString(),
      credentialSubject: payload.credentialSubject,
    },
    proofFormat: 'jwt',
  })

  return { payload, vc }
}

/**
 * Creates the VC payload with attributes.
 */
export function generateVCPayload(holderDID: string, attributes?: Record<string, any>): Record<string, any> {
  return {
    credentialSubject: {
      id: holderDID,
      ...attributes,
    },
  }
}

