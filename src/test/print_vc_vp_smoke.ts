import { cleanup, setup_bls_agents } from './enviroment_setup.js'
import {
  VCAggregateKeysToSignatures,
  getBlsKeyHex,
} from './issuers_test.js'
import { createMultiHolderPresentation, HolderInfo } from './holder_test.js'
import {
  verifyMultiSignatureVC,
  verifyPoOVP,
  PoOMultiHolderVP,
} from './verifier_test.js'

function backendLabel(): string {
  return process.env.VERAMO_BLS_BACKEND ?? 'chainsafe(default)'
}

async function main() {
  console.log(`\n=== Smoke: VC/VP create + verify (backend=${backendLabel()}) ===\n`)

  const issuers = await setup_bls_agents(2)
  const holder = (await setup_bls_agents(1))[0]
  const holdersRaw = await setup_bls_agents(2)
  const holders: HolderInfo[] = holdersRaw.map((h) => ({ did: h.did, kid_bls: h.kid_bls }))

  // touch a key (keeps parity with other tests)
  await getBlsKeyHex(issuers[0].kid_bls)


  // ---- VC (PoO) ----
  const vcPoO = (await VCAggregateKeysToSignatures(issuers, holder.did, 2, 14)) as any
  console.log('\n--- VC (PoO) ---')
  console.log('proof.type:', (vcPoO.proof as any)?.type)
  console.log(JSON.stringify(vcPoO, null, 2))
  await verifyMultiSignatureVC(vcPoO)

  // ---- VP (PoO) ----
  const vpPoO = (await createMultiHolderPresentation(holders, true, undefined, undefined, vcPoO)) as PoOMultiHolderVP
  console.log('\n--- VP (PoO) ---')
  console.log('proof.type:', (vpPoO.proof as any)?.type)
  console.log(JSON.stringify(vpPoO, null, 2))
  await verifyPoOVP(vpPoO)

  await cleanup()
}

main().catch(async (e) => {
  console.error(e)
  try {
    await cleanup()
  } catch {}
  process.exit(1)
})
