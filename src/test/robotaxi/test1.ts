// test_vp.ts
import { cleanup, setup_bls_agents } from '../enviroment_setup.js'
import {
    getBlsKeyHex,
    VCAggregateKeysToSignaturesWithBenchmark,
} from '../issuers_test.js'
import { VerifiableCredential } from '@veramo/core-types'
import {
    storeCredential,
    createMultiHolderPresentation,
    HolderInfo,
    benchmarkStep,
} from '../holder_test.js'
import {
    PoOMultiHolderVP,
    verifyMultiSignatureVP,
    verifyPoOVP,
} from '../verifier_test.js'

// --------- tweakables ----------
const ISSUERS_N = 2
const HOLDERS_N = 2
const USE_POO = true
const CLAIMS_N = 2
const CLAIMS_SIZE = 14
// --------------------------------

type BenchmarkResults = Record<string, number>
const timings: BenchmarkResults = {}

// === attributes & issuanceDate to match your target ===
const ATTRIBUTES: Record<string, any> = {
    user_VC1:
        '0x5e5c6f7c87f2b8c4b4c1d2a6d2d9f9b0a3c7fc2ef2c6b53a2d3b1a6e8d9c7e21',
    time_limit: '2025-12-31T15:59:59Z',
    user_VC2:
        '0x5e5c6f7c87f2b8c4b4c1d2a6d2d9f9b0a3c7fc2ef2c6b53a2d3b1a6e8d9c7e21',
    user_vc2_time_limit: '2025-12-31T16:40:30Z',
    robotaxi_VC1:
        '0x5e5c6f7c87f2b8c4b4c1d2a6d2d9f9b0a3c7fc2ef2c6b53a2d3b1a6e8d9c7e21',
}

const VP_ISSUANCE_DATE = '2025-09-11T09:30:26.000Z' // exact string you requested

async function main() {
    // --- agents ---
    const issuers = await setup_bls_agents(ISSUERS_N)
    const holdersRaw = await setup_bls_agents(HOLDERS_N)
    const holders: HolderInfo[] = holdersRaw.map((h) => ({
        did: h.did,
        kid_bls: h.kid_bls,
    }))

    // touch a key (like your existing tests do) to ensure KMS path is hot
    await getBlsKeyHex(issuers[0].kid_bls)


    // --- create multi-holder VP (includes attributes + issuanceDate) ---
    let vp!: PoOMultiHolderVP
    await benchmarkStep(
        `Create VP (holders=${HOLDERS_N}, PoO=${USE_POO})`,
        timings,
        async () => {
            // Pass: holders, usePoO, timings, aggregatedKey?, vc?, attributes, issuanceDate
            // - aggregatedKey left undefined => computed inside for parity unless your helpers pass it
            // - vc passed as undefined if you don't want to embed; pass VC to embed it
            vp = (await createMultiHolderPresentation(
                holders,
                USE_POO,
                timings,
                /* aggregatedKey */ undefined,
                /* vc */ undefined, // or VC if you want it embedded
                /* attributes */ ATTRIBUTES,
            )) as PoOMultiHolderVP

            return vp
        },
    )

    // --- verify VP ---
    if (USE_POO) {
        await benchmarkStep('Verify VP (PoO + BLS agg)', timings, async () => {
            const res = await verifyPoOVP(vp)
            if (!res?.verified) {
                throw new Error(
                    `VP PoO+BLS verification failed: ${JSON.stringify(
                        res?.error ?? res,
                    )}`,
                )
            }
            return res
        })
    } else {
        await benchmarkStep('Verify VP (BLS agg only)', timings, async () => {
            const res = await verifyMultiSignatureVP(vp)
            if (!res?.verified) {
                throw new Error(
                    `VP BLS verification failed: ${JSON.stringify(res?.error ?? res)}`,
                )
            }
            return res
        })
    }

    // --- results ---
    console.table(timings)

    await cleanup()
}

main().catch(async (e) => {
    console.error(e)
    try {
        await cleanup()
    } catch {}
    process.exit(1)
})
