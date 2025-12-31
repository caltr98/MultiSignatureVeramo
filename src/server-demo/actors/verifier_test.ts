import { VerifiablePresentation, VerifiableCredential } from '@veramo/core'
import { agent } from '../../veramo/setup.js'

/** Verify a standard VP (jwt/lds) */
export async function verifyVP(vp: VerifiablePresentation): Promise<any> {
  const result = await agent.verifyPresentation({ presentation: vp })
  console.log('Verifiable Presentation Verification Result:', result.verified)
  return result
}

/** Narrow types matching the custom plugin’s VP shape */
export interface MultiHolderVP extends VerifiablePresentation {
  multi_holders: string[]
}
export interface PoOMultiHolderVP extends MultiHolderVP {
  aggregated_bls_public_key: string
}

/** Verify a multi-holder VP with aggregated BLS signature (no PoO) */
export async function verifyMultiSignatureVP(vp: MultiHolderVP): Promise<any> {
  const result = await agent.verifyMultisignaturePresentation({ presentation: vp } as any)
  console.log('Multi-Holder BLS VP Verification Result:', result)
  return result
}

/** Verify a multi-holder VP with PoO + aggregated BLS signature */
export async function verifyPoOVP(vp: PoOMultiHolderVP): Promise<any> {
  const result = await agent.verifyProofOfOwnershipMultisignaturePresentation({ presentation: vp } as any)
  console.log('Multi-Holder PoO+BLS VP Verification Result:', result)
  return result
}

/** Verify all VCs embedded in a VP. */
export async function verifyVCsFromVP(vp: VerifiablePresentation): Promise<boolean> {
  const creds = Array.isArray((vp as any).verifiableCredential) ? (vp as any).verifiableCredential : []
  if (creds.length === 0) {
    throw new Error('VP has no embedded verifiableCredential entries')
  }

  for (const cred of creds) {
    const vc = cred as VerifiableCredential
    try {
      const r = await agent.verifyCredential({ credential: vc })
      if (!r.verified) return false
    } catch {
      return false
    }
  }
  return true
}

export async function verifyVCs(vcs: VerifiableCredential[]): Promise<boolean> {
  if (vcs.length === 0) {
    throw new Error('No VCs provided')
  }
  for (const vc of vcs) {
    try {
      const r = await agent.verifyCredential({ credential: vc })
      if (!r.verified) return false
    } catch {
      return false
    }
  }
  return true
}

