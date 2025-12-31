import { agent } from '../veramo/setup.js';
import { hexToBytes } from '@veramo/utils';
function resolveBlsBackend(value) {
    return value === 'noble' ? 'noble' : 'chainsafe';
}
function strip0x(hex) {
    return hex.startsWith('0x') ? hex.slice(2) : hex;
}
let chainsafeBlsPromise;
async function getChainsafeBls() {
    if (!chainsafeBlsPromise) {
        chainsafeBlsPromise = import('@chainsafe/bls').then((m) => m?.default ?? m);
    }
    return chainsafeBlsPromise;
}
let nobleBlsPromise;
async function getNobleBls() {
    if (!nobleBlsPromise) {
        nobleBlsPromise = import('@noble/curves/bls12-381').then((m) => m.bls12_381);
    }
    return nobleBlsPromise;
}
async function getBlsKeyHex(kid) {
    const key = await agent.keyManagerGet({ kid });
    return key.publicKeyHex;
}
/**
 * Create a Proof of Possession for a single Actor (by BLS key kid).
 *
 * - Binds the proof to the exact BLS public key and a caller-provided nonce.
 * - Uses a canonical JSON message for deterministic signing.
 * - Returns the message (what was signed), the signature, and the publicKeyHex.
 */
export async function createProofOfPossessionPerActor(kid_bls, nonce) {
    if (!kid_bls)
        throw new Error('kid_bls is required');
    if (!nonce)
        throw new Error('nonce is required');
    const publicKeyHex = await getBlsKeyHex(kid_bls);
    const messageObj = {
        type: 'BLS-ProofOfPossession',
        alg: 'BLS_SIGNATURE',
        publicKeyHex,
        nonce,
    };
    const message = JSON.stringify(messageObj);
    const signature = await agent.keyManagerSign({
        keyRef: kid_bls,
        data: message,
        algorithm: 'BLS_SIGNATURE',
        encoding: 'utf-8',
    });
    return { message, signature, publicKeyHex };
}
/**
 * Verify a Proof of Possession (PoP) produced by createProofOfPossessionPerActor.
 */
export async function verifyProofOfPossessionStrict(message, signatureHex, expectedNonce, expectedPublicKeyHex) {
    if (!message)
        return { valid: false, reason: 'Missing message', publicKeyHex: '', nonce: '' };
    if (!signatureHex)
        return { valid: false, reason: 'Missing signatureHex', publicKeyHex: '', nonce: '' };
    if (!expectedNonce)
        return { valid: false, reason: 'Missing expectedNonce', publicKeyHex: '', nonce: '' };
    if (!expectedPublicKeyHex)
        return { valid: false, reason: 'Missing expectedPublicKeyHex', publicKeyHex: '', nonce: '' };
    let parsed;
    try {
        parsed = JSON.parse(message);
    }
    catch {
        return { valid: false, reason: 'Message is not valid JSON', publicKeyHex: '', nonce: '' };
    }
    if (parsed?.type !== 'BLS-ProofOfPossession' || parsed?.alg !== 'BLS_SIGNATURE') {
        return { valid: false, reason: 'Invalid PoP domain fields', publicKeyHex: '', nonce: '' };
    }
    const publicKeyHexInMsg = parsed?.publicKeyHex;
    const nonceInMsg = parsed?.nonce;
    if (!publicKeyHexInMsg)
        return { valid: false, reason: 'Missing publicKeyHex in message', publicKeyHex: '', nonce: nonceInMsg || '' };
    if (!nonceInMsg)
        return { valid: false, reason: 'Missing nonce in message', publicKeyHex: publicKeyHexInMsg, nonce: '' };
    if (publicKeyHexInMsg !== expectedPublicKeyHex) {
        return { valid: false, reason: 'Public key mismatch', publicKeyHex: publicKeyHexInMsg, nonce: nonceInMsg };
    }
    if (nonceInMsg !== expectedNonce) {
        return { valid: false, reason: 'Nonce mismatch', publicKeyHex: publicKeyHexInMsg, nonce: nonceInMsg };
    }
    const backend = resolveBlsBackend(process.env.VERAMO_BLS_BACKEND);
    const pkHex = strip0x(publicKeyHexInMsg);
    const sigHex = strip0x(signatureHex);
    try {
        const msgBytes = new TextEncoder().encode(message);
        if (backend === 'noble') {
            const bls = await getNobleBls();
            const ok = bls.verify(hexToBytes(sigHex), msgBytes, hexToBytes(pkHex));
            return ok
                ? { valid: true, publicKeyHex: publicKeyHexInMsg, nonce: nonceInMsg }
                : { valid: false, reason: 'BLS verification failed', publicKeyHex: publicKeyHexInMsg, nonce: nonceInMsg };
        }
        else {
            const bls = await getChainsafeBls();
            const pk = bls.PublicKey.fromHex(pkHex);
            const sig = bls.Signature.fromHex(sigHex);
            const ok = bls.verify(pk, msgBytes, sig);
            return ok
                ? { valid: true, publicKeyHex: publicKeyHexInMsg, nonce: nonceInMsg }
                : { valid: false, reason: 'BLS verification failed', publicKeyHex: publicKeyHexInMsg, nonce: nonceInMsg };
        }
    }
    catch (e) {
        return { valid: false, reason: `Verification error: ${e?.message || e}`, publicKeyHex: publicKeyHexInMsg, nonce: nonceInMsg };
    }
}
