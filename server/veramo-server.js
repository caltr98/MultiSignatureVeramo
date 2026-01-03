// veramo-simple-server.ts
// Run: ts-node veramo-simple-server.ts (or compile and run with node)
import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import { createProofOfPossessionPerActor, verifyProofOfPossessionStrict } from './ProofOfPossessionProtocol.js';
// helper modules
import { aggregateBlsKeys, IndividualBlsVPSignatures, buildVPPayloadWithAggKey, createPoO, createMultiHolderPresentation, storeCredential, createSingleHolderPresentationFromStoredVCs } from './actors/holder_test.js';
import { verifyPoOVP, verifyMultiSignatureVP, verifyVCsFromVP, verifyVCs, verifyVP } from './actors/verifier_test.js';
import { singleActorSetup } from './single_actor_setup.js';
import { createVC } from './actors/issuers_test.js';
import * as fs from "node:fs";
import path from "node:path"; // adjust path
const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: '100mb' }));
// Health
app.get('/health', (_req, res) => {
    res.json({ ok: true, time: new Date().toISOString() });
});
/**
 * POST /setup/single-actor
 * Body:
 * {
 *   "name"?: string // optional alias, default = "actor1"
 * }
 *
 * Returns:
 * {
 *   ok: true,
 *   did: string,
 *   kid_bls: string,
 *   bls_pub_key: string,
 *   kid_eth: string
 * }
 */
app.post('/setup', async (req, res) => {
    try {
        const name = req.body?.name || 'actor1';
        const actorInfo = await singleActorSetup(name);
        res.json({ ok: true, ...actorInfo });
    }
    catch (e) {
        res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});
/**
 * POST /bls/aggregate
 * Body:
 * {
 *   "keys": string[]   // list of BLS public keys (hex)
 * }
 *
 * Returns:
 *   200: { ok: true, aggregatedKey }
 *   400: { ok: false, error }
 *   500: { ok: false, error }
 */
app.post('/bls/aggregate', async (req, res) => {
    try {
        const { keys } = req.body;
        if (!Array.isArray(keys) || keys.length === 0) {
            return res.status(400).json({ ok: false, error: 'Missing or invalid body.keys (expected string[])' });
        }
        const aggregatedKey = await aggregateBlsKeys(keys);
        res.json({ ok: true, aggregatedKey });
    }
    catch (e) {
        res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});
/**
 * POST /vp/sign/bls
 * Body:
 * {
 *   "presentation": object,   // VP payload INCLUDING aggregated_bls_public_key and multi_holders
 *   "did": string,            // Holder DID
 *   "kid_bls": string         // Holder BLS key reference
 * }
 *
 * Returns:
 *   200: { ok: true, signature }
 *   400: { ok: false, error }  // Missing required fields
 *   500: { ok: false, error }  // Internal server error
 */
app.post('/vp/signbls', async (req, res) => {
    try {
        const { presentation, did, kid_bls } = req.body;
        if (!presentation || !did || !kid_bls) {
            return res.status(400).json({ ok: false, error: "Missing required fields: presentation, did, kid_bls" });
        }
        const { signature, payloadToSign } = await IndividualBlsVPSignatures(presentation, did, kid_bls);
        res.json({ ok: true, signature, payloadToSign });
    }
    catch (e) {
        res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});
/**
 * POST /vp/poo
 * Body:
 * {
 *   "did": string,         // Holder DID
 *   "kid_eth": string,     // Ethereum key reference for signing
 *   "payloadToSign": string // JSON payload-to-sign
 * }
 *
 * Returns:
 *   200: { ok: true, signature }
 *   500: { ok: false, error: string }
 */
app.post('/vp/poo', async (req, res) => {
    try {
        const { did, kid_eth, payloadToSign } = req.body;
        if (!did || !kid_eth || !payloadToSign) {
            return res.status(400).json({ ok: false, error: "Missing required fields: did, kid_eth, payloadToSign" });
        }
        const signature = await createPoO(did, kid_eth, payloadToSign);
        res.json({ ok: true, signature });
    }
    catch (e) {
        res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});
/**
 * POST /vp/payload
 * Body:
 * {
 *   "holder_dids": string[],   // Array of holder DIDs
 *   "aggregatedKey": string,   // Aggregated BLS public key
 *   "vc"?: object              // Optional Verifiable Credential to embed
 *   "attributes"?: object      // Optional extra attributes to inject into the VP
 * }
 *
 * Returns:
 *   200: { ok: true, payload }
 *   400: { ok: false, error }  // Missing required fields
 *   500: { ok: false, error }  // Internal server error
 */
app.post('/vp/generatepayload', async (req, res) => {
    try {
        const { holder_dids, aggregatedKey, vcs, attributes } = req.body;
        if (!Array.isArray(holder_dids) || !aggregatedKey) {
            return res.status(400).json({ ok: false, error: "Missing required fields: holder_dids[], aggregatedKey" });
        }
        const payload = buildVPPayloadWithAggKey(holder_dids, aggregatedKey, vcs, attributes);
        res.json({ ok: true, payload });
    }
    catch (e) {
        res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});
/**
 * POST /vp/createfullvp
 * Body:
 * {
 *   // REQUIRED INPUTS
 *   "holders_dids": string[],             // DIDs of all holders to include
 *   "blssignatures": string[] | object[], // BLS signatures used for aggregation
 *   "aggkey": string,                     // Aggregated public key
 *   "proofsofownership": string[] | object[], // PoO proofs for the holders
 *    "payload": string //payload of the VP that was signed with BLS keys and with PoO proofs
 *   // OPTIONAL INPUTS
 *   "attributes"?: object,                // Extra attributes to inject into the VP
 *   "vcs"?: object | object[],            // Verifiable Credential(s) to embed in the VP
 *
 *   // NOTE: usePoO is always true in code; there is no request toggle.
 *   // NOTE: any "embedVc"/"embedVC" flag is ignored; supply "vcs" instead.
 * }
 *
 * Behavior:
 *   - Builds a multi-holder VP via createMultiHolderPresentation(
 *       holders_dids, true, aggkey, blssignatures, proofsofownership, vcs, attributes
 *     )
 *
 * Returns:
 *   200: { ok: true, vp }
 *   500: { ok: false, error: string }
 */
app.post('/vp/createfullvp', async (req, res) => {
    try {
        const holders_dids = req.body.holders_dids;
        const usePoO = true;
        const blssignaturesRaw = req.body.blssignatures;
        const blssignatures = Array.isArray(blssignaturesRaw) ? blssignaturesRaw : JSON.parse(blssignaturesRaw);
        const aggkey = req.body.aggkey;
        const proofsofownership = req.body.proofsofownership;
        const payload = req.body.payload;
        const attributes = typeof req.body?.attributes === 'object' && req.body?.attributes
            ? req.body.attributes
            : undefined;
        const vcs = typeof req.body?.vcs === 'object' && req.body?.vcs
            ? req.body.embedVC
            : undefined;
        // create the VP (no timings/bench here)
        const vp = (await createMultiHolderPresentation(holders_dids, usePoO, 
        /* aggregatedKey */ aggkey, 
        /* blssignatures */ blssignatures, 
        /* proofsofownership*/ proofsofownership, 
        /* payload */ payload));
        console.log("verify right here right now" + await JSON.stringify(verifyPoOVP(vp)));
        res.json({ ok: true, vp });
    }
    catch (e) {
        res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});
/**
 * POST /vp/multi/verify
 * Body:
 * {
 *   "usePoO"?: boolean (default true),
 *   "vp": multi holder vp object
 * }
 * Returns: { ok: true, verified, result }
 */
app.post('/vp/multi/verify', async (req, res) => {
    try {
        const usePoO = Boolean(req.body?.usePoO ?? true);
        const vp = req.body?.vp;
        if (!vp || typeof vp !== 'object') {
            return res.status(400).json({ ok: false, error: 'Missing body.vp' });
        }
        const result = usePoO ? await verifyPoOVP(vp) : await verifyMultiSignatureVP(vp);
        res.json({ ok: true, verified: !!result?.verified, result });
    }
    catch (e) {
        res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});
/**
 * POST /vp/verify
 * Body:
 * {
 *   "vp": single holder vp object
 * }
 * Returns: { ok: true, verified, result }
 */
app.post('/vp/verify', async (req, res) => {
    try {
        const vp = req.body?.vp;
        if (!vp || typeof vp !== 'object') {
            return res.status(400).json({ ok: false, error: 'Missing body.vp' });
        }
        const result = await verifyVP(vp);
        res.json({ ok: true, verified: !!result?.verified, result });
    }
    catch (e) {
        res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});
/**
 * POST /vc/create
 * Body:
 * {
 *   "issuerDid": string,        // REQUIRED
 *   "holderDid": string,        // REQUIRED
 *   "attributes": object        // REQUIRED - merged under credentialSubject
 * }
 *
 * Returns:
 *   200: { ok: true, payload, vc }
 *   400: { ok: false, error }
 *   500: { ok: false, error }
 */
app.post('/vc/create', async (req, res) => {
    try {
        const { issuerDid, holderDid, attributes } = req.body ?? {};
        if (!issuerDid || !holderDid) {
            return res
                .status(400)
                .json({ ok: false, error: 'Missing required fields: issuerDid, holderDid' });
        }
        if (attributes === null || typeof attributes !== 'object' || Array.isArray(attributes)) {
            return res
                .status(400)
                .json({ ok: false, error: 'Missing or invalid required field: attributes (must be an object)' });
        }
        // Call helper
        const { payload, vc } = await createVC(issuerDid, holderDid, attributes);
        res.json({ ok: true, payload, vc });
    }
    catch (e) {
        res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});
/**
 * POST /vc/store
 * Body:
 * {
 *   "vc": object   // Verifiable Credential
 * }
 *
 * Returns:
 *   200: { ok: true, result }
 *   400: { ok: false, error }
 *   500: { ok: false, error }
 */
app.post('/vc/store', async (req, res) => {
    try {
        const { vc } = req.body ?? {};
        if (!vc || typeof vc !== 'object') {
            return res
                .status(400)
                .json({ ok: false, error: 'Missing or invalid "vc" (must be an object)' });
        }
        // Call the HELPER (storeCredential)
        const result = await storeCredential(vc);
        res.json({ ok: true, result });
    }
    catch (e) {
        res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});
/**
 * POST /vp/from-all
 * Body:
 * {
 *   "holderDid": string,             // REQUIRED: DID of the presenter
 *   "proofFormat"?: "jwt" | "lds"    // OPTIONAL: default "jwt"
 * }
 *
 * Returns:
 *   200: { ok: true, vp }
 *   400: { ok: false, error }
 *   500: { ok: false, error }
 */
app.post('/vp/from-all', async (req, res) => {
    try {
        const { holderDid, proofFormat } = req.body ?? {};
        if (!holderDid || typeof holderDid !== 'string') {
            return res
                .status(400)
                .json({ ok: false, error: 'Missing or invalid "holderDid" (string required)' });
        }
        const vp = await createSingleHolderPresentationFromStoredVCs(holderDid, proofFormat ?? 'jwt');
        res.json({ ok: true, vp });
    }
    catch (e) {
        res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});
/**
 * POST /pop/create
 * Body:
 * {
 *   "kid_bls": string, // required
 *   "nonce": string     // required
 * }
 * Returns: { ok: true, message, signature, publicKeyHex }
 */
app.post('/pop/create', async (req, res) => {
    try {
        const { kid_bls, nonce } = req.body ?? {};
        if (!kid_bls || !nonce) {
            return res.status(400).json({ ok: false, error: 'Missing required fields: kid_bls, nonce' });
        }
        const { message, signature, publicKeyHex } = await createProofOfPossessionPerActor(kid_bls, nonce);
        res.json({ ok: true, message: message, signature: signature, publicKeyHex: publicKeyHex });
    }
    catch (e) {
        res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});
/**
 * POST /pop/verify
 * Body:
 * {
 *   "message": string,             // required: exact JSON that was signed
 *   "signatureHex": string,        // required: hex BLS signature
 *   "expectedNonce": string,       // required
 *   "expectedPublicKeyHex": string // required
 * }
 * Returns: { ok: true, valid, publicKeyHex, nonce } (or ok:false,error)
 */
app.post('/pop/verify', async (req, res) => {
    try {
        const { message, signatureHex, expectedNonce, expectedPublicKeyHex } = req.body ?? {};
        if (!message || !signatureHex || !expectedNonce || !expectedPublicKeyHex) {
            return res.status(400).json({ ok: false, error: 'Missing required fields: message, signatureHex, expectedNonce, expectedPublicKeyHex' });
        }
        const result = await verifyProofOfPossessionStrict(message, signatureHex, expectedNonce, expectedPublicKeyHex);
        res.json({ ok: true, ...result });
    }
    catch (e) {
        res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});
/**
 * POST /vp/verify-vcs
 * Body:
 * {
 *   "vp": object   // Verifiable Presentation containing an array "verifiableCredential"
 * }
 * Returns:
 *   200: { ok: true, verified: boolean }
 *   400: { ok: false, error }
 *   500: { ok: false, error }
 */
app.post('/vp/verify-vcs', async (req, res) => {
    try {
        const vp = req.body?.vp;
        if (!vp || typeof vp !== 'object') {
            return res.status(400).json({ ok: false, error: 'Missing body.vp' });
        }
        const verified = await verifyVCsFromVP(vp);
        res.json({ ok: true, verified });
    }
    catch (e) {
        res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});
/**
 * POST /vc/verify-vcs
 * Body:
 * {
 *   "vcs": object   // An array of "verifiableCredential"
 * }
 * Returns:
 *   200: { ok: true, verified: boolean }
 *   400: { ok: false, error }
 *   500: { ok: false, error }
 */
app.post('/vc/verify-vcs', async (req, res) => {
    try {
        const vcs = req.body?.vcs;
        if (!vcs) {
            return res.status(400).json({ ok: false, error: 'Missing body.vcs' });
        }
        const verified = await verifyVCs(vcs);
        res.json({ ok: true, verified });
    }
    catch (e) {
        res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});
function shutdown() {
    console.log("Shutting down...");
    const dbFile = process.env.DB_FILE || 'database.sqlite';
    const dbPath = path.resolve(dbFile);
    server.close(() => {
        console.log("Server closed.");
        // delete DB file if it exists
        try {
            if (fs.existsSync(dbPath)) {
                fs.unlinkSync(dbPath);
                console.log(`Deleted database file: ${dbPath}`);
            }
            else {
                console.log(`No DB file to delete (${dbPath})`);
            }
        }
        catch (e) {
            console.log(`Failed to delete DB: ${e?.message || e}`);
        }
        process.exit(0);
    });
}
app.post("/stop", (_req, res) => {
    res.json({ ok: true, message: "Shutting down Veramo..." });
    // give the response time to flush before shutdown
    setTimeout(shutdown, 100);
});
const PORT = Number(process.env.PORT || 3001);
const server = app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
