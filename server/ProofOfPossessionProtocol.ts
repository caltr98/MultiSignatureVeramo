
// Assuming you already have this helper in the same file:
import {agent} from "../veramo/setup.js";
// Verification of a PoP (Proof of Possession) using @chainsafe/bls, mirroring your VC verifiers.

import bls from '@chainsafe/bls'

async function getBlsKeyHex(kid: string): Promise<string> {
    const key = await agent.keyManagerGet({ kid })
    return key.publicKeyHex
}

/**
 * Create a Proof of Possession for a single Actor (by BLS key kid).
 *
 * - Binds the proof to the exact BLS public key and a caller-provided nonce.
 * - Uses a canonical JSON message for deterministic signing.
 * - Returns the message (what was signed), the signature, and the publicKeyHex.
 */
export async function createProofOfPossessionPerActor(
    kid_bls: string,
    nonce: string,
): Promise<{ message: string; signature: string; publicKeyHex: string }> {
    if (!kid_bls) throw new Error('kid_bls is required')
    if (!nonce) throw new Error('nonce is required')

    const publicKeyHex = await getBlsKeyHex(kid_bls)

    // Domain-separated, canonical message
    const messageObj = {
        type: 'BLS-ProofOfPossession',
        alg: 'BLS_SIGNATURE',
        publicKeyHex,
        nonce,
    }
    const message = JSON.stringify(messageObj) // deterministic key order as written

    const signature = await agent.keyManagerSign({
        keyRef: kid_bls,
        data: message,
        algorithm: 'BLS_SIGNATURE',
        encoding: 'utf-8',
    })

    return { message, signature, publicKeyHex }
}


/**
 * Verify a Proof of Possession (PoP) produced by createProofOfPossessionPerActor.
 *
 * REQUIRED:
 *  - expectedNonce: freshness binding
 *  - expectedPublicKeyHex: public key pinning
 *
 * @param message  The exact JSON string that was signed
 * @param signatureHex  Hex-encoded BLS signature
 * @param expectedNonce  Must match message.nonce
 * @param expectedPublicKeyHex  Must match message.publicKeyHex (and is used for verification)
 *
 * Returns: { valid, reason?, publicKeyHex, nonce }
 */
export async function verifyProofOfPossessionStrict(
    message: string,
    signatureHex: string,
    expectedNonce: string,
    expectedPublicKeyHex: string
): Promise<{ valid: boolean; reason?: string; publicKeyHex: string; nonce: string }> {

    if (!message) return { valid: false, reason: 'Missing message', publicKeyHex: '', nonce: '' }
    if (!signatureHex) return { valid: false, reason: 'Missing signatureHex', publicKeyHex: '', nonce: '' }
    if (!expectedNonce) return { valid: false, reason: 'Missing expectedNonce', publicKeyHex: '', nonce: '' }
    if (!expectedPublicKeyHex) return { valid: false, reason: 'Missing expectedPublicKeyHex', publicKeyHex: '', nonce: '' }

    // 1) Parse & check domain separation
    let parsed: any
    try {
        parsed = JSON.parse(message)
    } catch {
        return { valid: false, reason: 'Message is not valid JSON', publicKeyHex: '', nonce: '' }
    }

    if (parsed?.type !== 'BLS-ProofOfPossession' || parsed?.alg !== 'BLS_SIGNATURE') {
        return { valid: false, reason: 'Invalid PoP domain fields', publicKeyHex: '', nonce: '' }
    }

    const publicKeyHexInMsg: string | undefined = parsed?.publicKeyHex
    const nonceInMsg: string | undefined = parsed?.nonce
    if (!publicKeyHexInMsg) return { valid: false, reason: 'Missing publicKeyHex in message', publicKeyHex: '', nonce: nonceInMsg || '' }
    if (!nonceInMsg) return { valid: false, reason: 'Missing nonce in message', publicKeyHex: publicKeyHexInMsg, nonce: '' }

    // 2) Enforce expectations (pinning + freshness)
    if (publicKeyHexInMsg !== expectedPublicKeyHex) {
        return { valid: false, reason: 'Public key mismatch', publicKeyHex: publicKeyHexInMsg, nonce: nonceInMsg }
    }
    if (nonceInMsg !== expectedNonce) {
        return { valid: false, reason: 'Nonce mismatch', publicKeyHex: publicKeyHexInMsg, nonce: nonceInMsg }
    }

    // 3) BLS signature verification
    try {
        const pk = bls.PublicKey.fromHex((publicKeyHexInMsg))
        const sig = bls.Signature.fromHex((signatureHex))
        const msgBytes = new TextEncoder().encode(message) // verify over the exact string you signed

        const ok = bls.verify(pk, msgBytes, sig)
        return ok
            ? { valid: true, publicKeyHex: publicKeyHexInMsg, nonce: nonceInMsg }
            : { valid: false, reason: 'BLS verification failed', publicKeyHex: publicKeyHexInMsg, nonce: nonceInMsg }
    } catch (e: any) {
        return { valid: false, reason: `Verification error: ${e?.message || e}`, publicKeyHex: publicKeyHexInMsg, nonce: nonceInMsg }
    }
}

