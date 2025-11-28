// Multi-agent orchestration aligned with the full benchmark flow used in tests.

import fs from 'fs'
import path from 'path'
import type { VerifiableCredential, VerifiablePresentation } from '@veramo/core-types'
import { benchmarkStep, VCAggregateKeysToSignaturesWithBenchmark } from './test/issuers_test.js'
import { cleanup, setup_bls_agents } from './test/enviroment_setup.js'
import { createSingleHolderPresentation, storeCredential } from './test/holder_test.js'
import { verifyMultiSignatureVC, verifyVP } from './test/verifier_test.js'
import { getBlsKeyHex } from './test/issuers_test.js'

export interface MultiAgentBenchmarkOptions {
  claims?: number
  size?: number
  issuers?: number
  runs?: number
  resultsCsvPath?: string
}

type BenchmarkResults = Record<string, number>

function parseNumber(value: number | undefined, defaultValue: number): number {
  return typeof value === 'number' && !Number.isNaN(value) ? value : defaultValue
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

export async function runMultiAgentBenchmark(options: MultiAgentBenchmarkOptions = {}) {
  const claims_n = parseNumber(options.claims, 2)
  const claims_size = parseNumber(options.size, 12)
  const n_issuers = parseNumber(options.issuers, 2)
  const RUNS = parseNumber(options.runs, 2)

  const RESULTS_CSV = path.resolve(options.resultsCsvPath ?? './benchmark_results.csv')

  if (!fs.existsSync(RESULTS_CSV)) {
    const header = 'Issuers,StepName,avg_ms,std_ms\n'
    fs.writeFileSync(RESULTS_CSV, header)
  }

  // create all agents for issuer, holder, and verifier
  const issuers = await setup_bls_agents(n_issuers)
  const holder = (await setup_bls_agents(1))[0]

  // ensure we can retrieve a BLS key
  await getBlsKeyHex(issuers[0].kid_bls)

  const allTimings: Record<string, number[]> = {}

  for (let i = 0; i < RUNS; i++) {
    const timings: BenchmarkResults = {}

    const res = await VCAggregateKeysToSignaturesWithBenchmark(
      issuers,
      holder.did,
      claims_n,
      claims_size,
    )

    const VC = res.vc as VerifiableCredential
    Object.assign(timings, res.timings)

    await benchmarkStep('Store VC', timings, () => storeCredential(VC))

    let vp: VerifiablePresentation
    await benchmarkStep('Create VP', timings, async () => {
      vp = await createSingleHolderPresentation(VC, holder.did)
      return vp
    })

    await benchmarkStep('Verify VP', timings, async () => verifyVP(vp))

    let verified = false
    while (!verified) {
      const verificationResult = await verifyMultiSignatureVC(VC)

      if (verificationResult.timings) {
        for (const [label, time] of Object.entries(verificationResult.timings)) {
          timings[label] = time as number
        }
      }

      verified = Boolean(verificationResult?.verified)
      if (!verified) {
        await sleep(3000)
      }
    }

    for (const [label, value] of Object.entries(timings)) {
      if (!allTimings[label]) {
        allTimings[label] = []
      }
      allTimings[label].push(value)
    }

    await sleep(100)
  }

  const summary: Record<string, { avg_in_ms: number; std_dev: number }> = {}
  for (const [label, values] of Object.entries(allTimings)) {
    const avg_in_ms = values.reduce((a, b) => a + b, 0) / values.length
    const std_dev = Math.sqrt(
      values.reduce((sum, x) => sum + Math.pow(x - avg_in_ms, 2), 0) / values.length,
    )
    summary[label] = { avg_in_ms, std_dev }
  }

  const csvLines: string[] = []
  for (const [step, stats] of Object.entries(summary)) {
    const avg = stats.avg_in_ms.toFixed(6)
    const std = stats.std_dev.toFixed(6)
    csvLines.push(`${n_issuers},${step},${avg},${std}`)
  }

  fs.appendFileSync(RESULTS_CSV, csvLines.join('\n') + '\n')

  await cleanup()

  return {
    issuers: n_issuers,
    claims: claims_n,
    size: claims_size,
    runs: RUNS,
    summary,
    resultsPath: RESULTS_CSV,
  }
}
