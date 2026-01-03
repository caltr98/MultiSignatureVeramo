// generate VC payload with a set number of fixed-size claims
function createSeededRandom(seed) {
    return () => {
        const x = Math.sin(seed++) * 10000;
        return x - Math.floor(x);
    };
}
function generateFixedString(rand, length) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(rand() * chars.length));
    }
    return result;
}
function generateClaims(seed, count, valueSize) {
    const rand = createSeededRandom(seed);
    const claims = {};
    for (let i = 0; i < count; i++) {
        const key = `claim_${i}`;
        const value = generateFixedString(rand, valueSize);
        claims[key] = value;
    }
    return claims;
}
export async function generateVCPayload(holderDID, claimCount, valueSize, seed) {
    const claims = generateClaims(seed, claimCount, valueSize);
    return {
        credentialSubject: {
            id: holderDID,
            ...claims,
        },
    };
}
