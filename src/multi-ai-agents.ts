// Multi-agent orchestration for issuing, presenting, and verifying a multi-signature VC
// using the same helpers as the end-to-end test workflow (without benchmark instrumentation).

import type { VerifiableCredential, VerifiablePresentation } from '@veramo/core-types'
import { VCAggregateKeysToSignatures, getBlsKeyHex } from './test/issuers_test.js'
import { cleanup, setup_bls_agents } from './test/enviroment_setup.js'
import { createSingleHolderPresentation, storeCredential } from './test/holder_test.js'
import { verifyMultiSignatureVC, verifyVP } from './test/verifier_test.js'

export interface MultiAgentIssuanceOptions {
  claims?: number
  size?: number
  issuers?: number
  seed?: number
  maxVerificationAttempts?: number
  retryDelayMs?: number
}

export interface MultiAgentIssuanceResult {
  credential: VerifiableCredential
  presentation: VerifiablePresentation
  vpVerification: unknown
  vcVerification: unknown
  issuers: number
  claims: number
  size: number
  seed: number
}

function parseNumber(value: number | undefined, defaultValue: number): number {
  return typeof value === 'number' && !Number.isNaN(value) ? value : defaultValue
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/**
 * Executes the multi-agent credential issuance flow using the same calls as the full test suite.
 */
export async function runMultiAgentIssuance(
  options: MultiAgentIssuanceOptions = {},
): Promise<MultiAgentIssuanceResult> {
  const claims_n = parseNumber(options.claims, 2)
  const claims_size = parseNumber(options.size, 12)
  const n_issuers = parseNumber(options.issuers, 2)
  const seed = parseNumber(options.seed, 42)
  const maxAttempts = parseNumber(options.maxVerificationAttempts, 3)
  const retryDelayMs = parseNumber(options.retryDelayMs, 3000)

  // create all agents for issuer and holder
  const issuers = await setup_bls_agents(n_issuers)
  const holder = (await setup_bls_agents(1))[0]

  await getBlsKeyHex(issuers[0].kid_bls)

  let presentation: VerifiablePresentation
  let vpVerification: unknown
  let vcVerification: unknown

  try {
    const vc = (await VCAggregateKeysToSignatures(
      issuers,
      holder.did,
      claims_n,
      claims_size,
      seed,
    )) as VerifiableCredential

    await storeCredential(vc)
    presentation = await createSingleHolderPresentation(vc, holder.did)
    vpVerification = await verifyVP(presentation)

    let attempts = 0
    while (attempts < maxAttempts) {
      vcVerification = await verifyMultiSignatureVC(vc)
      if ((vcVerification as { verified?: boolean } | undefined)?.verified) {
        break
      }
      attempts += 1
      if (attempts < maxAttempts) {
        await sleep(retryDelayMs)
      }
    }

    return {
      credential: vc,
      presentation,
      vpVerification,
      vcVerification,
      issuers: n_issuers,
      claims: claims_n,
      size: claims_size,
      seed,
    }
  } finally {
    await cleanup()
  }
}
