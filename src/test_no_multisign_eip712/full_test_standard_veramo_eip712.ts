import { cleanup, setup_agents } from './enviroment_setup.js'
import { storeCredential, createPresentation } from './holder_test.js'
import { verifyVP, verifyAllVCsInVP } from './verifier_test.js'

import fs from 'fs'
import path from 'path'
import { VerifiableCredential, VerifiablePresentation } from '@veramo/core-types'
import { generateVCPayload } from './generate_VC_payload.js'
import { agent } from '../veramo/setup_eip712.js'
import { fileURLToPath } from 'url'

function parseArg(name: string, defaultValue: number): number {
  const index = process.argv.indexOf(`--${name}`)
  if (index !== -1 && process.argv[index + 1]) {
    const val = parseInt(process.argv[index + 1])
    if (!isNaN(val)) return val
  }
  return defaultValue
}

function parseBoolArg(name: string, defaultValue: boolean): boolean {
  const index = process.argv.indexOf(`--${name}`)
  if (index !== -1) {
    const next = process.argv[index + 1]
    if (next === undefined) return true
    if (next === '1' || next === 'true') return true
    if (next === '0' || next === 'false') return false
  }
  return defaultValue
}

const claims_n = parseArg('claims', 32)
const claims_size = parseArg('size', 1024)
const n_issuers = parseArg('issuers', 8)
const RUNS = parseArg('runs', 5)
const PRINT_SAMPLE = parseBoolArg('printSample', false)
const LOG_RUNS = parseBoolArg('logRuns', true)

const RESULTS_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..', 'experimental_results')
fs.mkdirSync(RESULTS_DIR, { recursive: true })
const RESULTS_CSV = path.join(RESULTS_DIR, `benchmark_standard_eip712_claims${claims_n}_size${claims_size}.csv`)
if (!fs.existsSync(RESULTS_CSV)) {
  fs.writeFileSync(RESULTS_CSV, 'Issuers,StepName,avg_ms,std_ms\n')
}

type BenchmarkResults = Record<string, number>
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

async function benchmarkStep<T>(label: string, results: BenchmarkResults, fn: () => Promise<T>): Promise<T> {
  const start = performance.now()
  const result = await fn()
  const end = performance.now()
  results[label] = end - start
  return result
}

const allTimings: Record<string, number[]> = {}
const issuers = await setup_agents(n_issuers)
const holder = (await setup_agents(1))[0]

for (let i = 0; i < RUNS; i++) {
  if (LOG_RUNS) {
    console.log(`\nRun ${i + 1} of ${RUNS}`)
  }
  const timings: BenchmarkResults = {}
  const credentials: VerifiableCredential[] = []

  // Keep the same step names as `src/test_no_multisign/full_test_standard_veramo.ts`
  // so the CSVs are directly comparable.
  timings['Issue VCs'] = 0
  timings['Store VCs'] = 0

  for (const issuer of issuers) {
    const payload = await generateVCPayload(holder.did, claims_n, claims_size, 42)

    let start = performance.now()
    const vc = await agent.createVerifiableCredentialEIP712({
      credential: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential'],
        issuer: { id: issuer.did },
        credentialSubject: payload.credentialSubject,
      },
      keyRef: issuer.keyRef,
    } as any)
    let now = performance.now()
    timings['Issue VCs'] += now - start

    credentials.push(vc as any)
    if (PRINT_SAMPLE && issuer === issuers[0] && i === 0) {
      console.log('\nEIP712 VC sample:')
      console.log(JSON.stringify(vc, null, 2))
    }

    start = performance.now()
    await storeCredential(vc as any)
    now = performance.now()
    timings['Store VCs'] += now - start
  }

  const vp = await benchmarkStep('Create VP (N VCs)', timings, () =>
    createPresentation(credentials, holder.did, holder.keyRef),
  )

  await benchmarkStep('Verify VP (N VCs)', timings, () => verifyVP(vp as VerifiablePresentation))

  const results = await verifyAllVCsInVP(vp as VerifiablePresentation, timings)
  if (results.some((r) => !r.verified)) {
    throw new Error('One or more embedded VCs failed verification')
  }

  for (const [label, value] of Object.entries(timings)) {
    if (!allTimings[label]) allTimings[label] = []
    allTimings[label].push(value)
  }

  await sleep(200)
}

const summary: Record<string, { avg_in_ms: number; std_dev: number }> = {}
for (const [label, values] of Object.entries(allTimings)) {
  const avg_in_ms = values.reduce((a, b) => a + b, 0) / values.length
  const std_dev = Math.sqrt(values.reduce((sum, x) => sum + Math.pow(x - avg_in_ms, 2), 0) / values.length)
  summary[label] = { avg_in_ms, std_dev }
}

const csvLines = Object.entries(summary).map(([step, stats]) => {
  const avg = stats.avg_in_ms.toFixed(6)
  const std = stats.std_dev.toFixed(6)
  return `${n_issuers},${step},${avg},${std}`
})

fs.appendFileSync(RESULTS_CSV, csvLines.join('\n') + '\n')
console.log(`\n[Standard Veramo EIP712] Results for ${n_issuers} issuers`)
console.table(summary)

await cleanup()
