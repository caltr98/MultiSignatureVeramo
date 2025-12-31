// Simple client that drives the PoO+BLS multi-holder flow against `veramo-server.ts`.
//
// Compile then run in a second terminal (with server already running):
//   yarn tsc -p tsconfig.json
//   node src/server-demo/client.js

type SetupResponse = {
  ok: boolean
  did: string
  kid_bls: string
  bls_pub_key: string
  kid_eth: string
}

async function postJson<T>(baseUrl: string, path: string, body: any): Promise<T> {
  const res = await fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(process.env.API_KEY ? { 'x-api-key': process.env.API_KEY } : {}),
    },
    body: JSON.stringify(body),
  })
  const json = await res.json()
  if (!res.ok || json?.ok === false) {
    throw new Error(`${path} failed: ${JSON.stringify(json)}`)
  }
  return json as T
}

async function main() {
  const baseUrl = process.env.BASE_URL || 'http://localhost:3001'
  const holdersCount = Number(process.env.HOLDERS || 2)

  console.log(`baseUrl=${baseUrl}`)
  console.log(`VERAMO_BLS_BACKEND=${process.env.VERAMO_BLS_BACKEND ?? 'chainsafe(default)'}`)

  // ---- setup actors ----
  const issuer = await postJson<SetupResponse>(baseUrl, '/setup', { name: 'issuer' })
  const holders: SetupResponse[] = []
  for (let i = 0; i < holdersCount; i++) {
    holders.push(await postJson<SetupResponse>(baseUrl, '/setup', { name: `holder-${i}` }))
  }

  // ---- create a VC (JWT) ----
  const vcResp = await postJson<any>(baseUrl, '/vc/create', {
    issuerDid: issuer.did,
    holderDid: holders[0].did,
    attributes: { hello: 'world', ts: Date.now() },
  })
  const vc = vcResp.vc
  console.log('\nVC created')

  // ---- aggregate holder BLS pubkeys ----
  const aggResp = await postJson<any>(baseUrl, '/bls/aggregate', {
    keys: holders.map((h) => h.bls_pub_key),
  })
  const aggregatedKey = aggResp.aggregatedKey as string

  // ---- create VP payload ----
  const vpPayloadResp = await postJson<any>(baseUrl, '/vp/generatepayload', {
    holder_dids: holders.map((h) => h.did),
    aggregatedKey,
    vcs: [vc],
    attributes: { demo: 'server-demo' },
  })
  const vpPayload = vpPayloadResp.payload

  // ---- collect BLS signatures ----
  const blsSignatures: string[] = []
  let payloadToSign: string | undefined
  for (const h of holders) {
    const sigResp = await postJson<any>(baseUrl, '/vp/signbls', {
      presentation: vpPayload,
      did: h.did,
      kid_bls: h.kid_bls,
    })
    blsSignatures.push(sigResp.signature)
    if (!payloadToSign) payloadToSign = sigResp.payloadToSign
  }
  if (!payloadToSign) throw new Error('missing payloadToSign from /vp/signbls')

  // ---- collect PoOs ----
  const proofsOfOwnership: string[] = []
  for (const h of holders) {
    const pooResp = await postJson<any>(baseUrl, '/vp/poo', {
      did: h.did,
      kid_eth: h.kid_eth,
      payloadToSign,
    })
    proofsOfOwnership.push(pooResp.signature)
  }

  // ---- create full PoO VP ----
  const fullVpResp = await postJson<any>(baseUrl, '/vp/createfullvp', {
    holders_dids: holders.map((h) => h.did),
    blssignatures: blsSignatures,
    aggkey: aggregatedKey,
    proofsofownership: proofsOfOwnership,
    payload: vpPayload,
  })
  const vp = fullVpResp.vp
  console.log('\nVP created')
  console.log('VP.proof.type:', vp?.proof?.type)

  // ---- verify ----
  const verifyResp = await postJson<any>(baseUrl, '/vp/multi/verify', { usePoO: true, vp })
  console.log('\nVP verify result:', verifyResp.verified)
  console.log(JSON.stringify(verifyResp.result, null, 2))
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
