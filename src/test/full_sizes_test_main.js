import { cleanup, setup_bls_agents } from './enviroment_setup.js';
import crypto from "crypto";
import { getBlsKeyHex, VCAggregateKeysToSignaturesWithSizes, createProofsOfPossessionPerIssuer } from './issuers_test.js';
import fs from 'fs';
import path from 'path';
const SIZE_CSV = path.resolve('./message_sizes.csv');
if (!fs.existsSync(SIZE_CSV)) {
    fs.writeFileSync(SIZE_CSV, 'Issuers,StepName,Size_bytes\n');
}
function parseArg(name, def) {
    const i = process.argv.indexOf(`--${name}`);
    if (i !== -1 && process.argv[i + 1]) {
        const val = parseInt(process.argv[i + 1]);
        if (!isNaN(val))
            return val;
    }
    return def;
}
const claims_n = parseArg('claims', 3);
const claims_size = parseArg('size', 150);
const n_issuers = parseArg('issuers', 16);
console.log({ claims_n, claims_size, n_issuers });
//
function measureSize(label, obj, map) {
    const size = Buffer.byteLength(JSON.stringify(obj), 'utf8');
    map[label] = size;
}
const issuers = await setup_bls_agents(n_issuers);
const holder = (await setup_bls_agents(1))[0];
await getBlsKeyHex(issuers[0].kid_bls);
const res = await VCAggregateKeysToSignaturesWithSizes(issuers, holder.did, claims_n, claims_size);
const VC = res.vc;
// Begin Measurement
const sizes = {};
// 1. BLS Key Exchange = N × (N - 1) × pk^{bls}
const pk_example = await getBlsKeyHex(issuers[0].kid_bls);
const pk_size = Buffer.byteLength(JSON.stringify(pk_example), 'utf8');
//1.1 Generate a random nonce of 16 bytes so 32 hex chars)
const nonceBytes = 16;
const nonce = crypto.randomBytes(nonceBytes).toString("hex");
//1.2 Proof of Possession size
const pop = await createProofsOfPossessionPerIssuer(issuers[0].kid_bls, nonce);
const pop_size = Buffer.byteLength(pop, "utf8");
sizes["SingleProofOfPossession"] = pop_size;
//1.3 Total bytes per exchange = pk + PoP + nonce
const per_exchange = pk_size + pop_size + nonceBytes;
//1.4 Exchanges (summed up)
sizes["BLS Key Exchange + All PoP"] = n_issuers * (n_issuers - 1) * per_exchange;
/*
// 2. Claim Agreement = canonicalized VC payload = (N × N-1) × (claims x claim_size)
const payload = claims_n * claims_size * (n_issuers * n_issuers-1);
measureSize('Claim Agreement', payload, sizes); // Size for one instance
sizes['Claim Agreement'] = sizes['Claim Agreement'] * (n_issuers * (n_issuers-1));

// 3. Signatures to Orchestrator = N × σ^{bls}
const sig_bls = res.intermediates?.blsSignatures?.[0];
measureSize('Sig to OIss (1)', sig_bls, sizes);
sizes['Sig to OIss'] = n_issuers * sizes['Sig to OIss (1)'];



// 4. PoOs to Orchestrator = N × σ^{did}
const poo_example = res.intermediates?.proofsOfOwnership?.[0];
measureSize('PoO (1)', poo_example, sizes);
sizes['PoOs to OIss'] = n_issuers * sizes['PoO (1)'];

// 5. Final VC sent to holder (aggregated) = payload + agg sig + PoOs
measureSize('VC to Holder', VC, sizes);

// Clean up temp labels
delete sizes['Sig to OIss (1)'];
delete sizes['PoO (1)'];
*/
console.log(`Message Size Breakdown for ${n_issuers} issuers:`);
console.table(sizes);
// Write to CSV
const csvLines = Object.entries(sizes).map(([label, size]) => `${n_issuers},${label},${size}`);
fs.appendFileSync(SIZE_CSV, csvLines.join('\n') + '\n');
console.log(`Results appended to ${SIZE_CSV}`);
await cleanup();
