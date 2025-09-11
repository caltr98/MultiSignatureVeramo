// generateVC.ts

export interface VCParams {
    holderDID: string;
    claimCount: number;
    valueSize: number;
    seed?: number; // optional but deterministic — defaults to 42
}

/**
 * Create a seeded PRNG using Math.sin-based technique
 */
function createSeededRandom(seed: number): () => number {
    return () => {
        const x = Math.sin(seed++) * 10000;
        return x - Math.floor(x); // keep in [0,1)
    };
}

/**
 * Generate a fixed-length alphanumeric string using a seeded RNG
 */
function generateFixedString(rand: () => number, length: number): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(rand() * chars.length));
    }
    return result;
}

/**
 * Generate deterministic claims of fixed size using a seed
 */
function generateClaims(seed: number, count: number, valueSize: number): Record<string, string> {
    const rand = createSeededRandom(seed);
    const claims: Record<string, string> = {};

    for (let i = 0; i < count; i++) {
        const key = `claim_${i}`;
        const value = generateFixedString(rand, valueSize);
        claims[key] = value;
    }

    return claims;
}

/**
 * Creates the VC payload with multi_issuers and a set number of fixed-size claims
 */
export function generateVCPayload(
    holderDID: string,
    claimCount: number,
    valueSize: number,
    seed: number = 42
): Record<string, any> {
    const claims = generateClaims(seed, claimCount, valueSize);

    const payload = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential'],
        credentialSubject: {
            id: holderDID,
            ...claims,
        },
    };

    return payload;
}
