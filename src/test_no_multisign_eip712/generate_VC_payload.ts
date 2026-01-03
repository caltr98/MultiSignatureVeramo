// generate VC payload with a set number of fixed-size claims

export interface VCParams {
  holderDID: string
  claimCount: number
  valueSize: number
  seed?: number
}

function createSeededRandom(seed: number): () => number {
  return () => {
    const x = Math.sin(seed++) * 10000
    return x - Math.floor(x)
  }
}

function generateFixedString(rand: () => number, length: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  let result = ''
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(rand() * chars.length))
  }
  return result
}

function generateClaims(seed: number, count: number, valueSize: number): Record<string, string> {
  const rand = createSeededRandom(seed)
  const claims: Record<string, string> = {}
  for (let i = 0; i < count; i++) {
    const key = `claim_${i}`
    const value = generateFixedString(rand, valueSize)
    claims[key] = value
  }
  return claims
}

export async function generateVCPayload(
  holderDID: string,
  claimCount: number,
  valueSize: number,
  seed: number,
): Promise<Record<string, any>> {
  const claims = generateClaims(seed, claimCount, valueSize)
  return {
    credentialSubject: {
      id: holderDID,
      ...claims,
    },
  }
}

