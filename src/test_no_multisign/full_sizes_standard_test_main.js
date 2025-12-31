import { cleanup, setup_agents } from './enviroment_setup.js';
import { createPresentation } from './holder_test.js';
import { generateVCPayload } from './generate_VC_payload.js';
import { agent } from '../veramo/setup.js';
import fs from 'fs';
import path from 'path';
const SIZE_CSV = path.resolve('./message_sizes_standard.csv');
if (!fs.existsSync(SIZE_CSV)) {
    fs.writeFileSync(SIZE_CSV, 'Issuers,StepName,Size_bytes\n');
}
function parseArg(name, defaultValue) {
    const index = process.argv.indexOf(`--${name}`);
    if (index !== -1 && process.argv[index + 1]) {
        const val = parseInt(process.argv[index + 1]);
        if (!isNaN(val))
            return val;
    }
    return defaultValue;
}
const claims_n = parseArg('claims', 32);
const claims_size = parseArg('size', 1024);
const n_issuers = parseArg('issuers', 4);
function measureSize(label, obj, map) {
    const size = Buffer.byteLength(JSON.stringify(obj), 'utf8');
    map[label] = size;
}
const issuers = await setup_agents(n_issuers);
const holder = (await setup_agents(1))[0];
const credentials = [];
let total_vc_size = 0;
for (const issuer of issuers) {
    const payload = await generateVCPayload(holder.did, claims_n, claims_size, 42);
    const vc = await agent.createVerifiableCredential({
        credential: {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            type: ['VerifiableCredential'],
            issuer: { id: issuer.did },
            credentialSubject: payload.credentialSubject,
        },
        proofFormat: 'jwt',
    });
    credentials.push(vc);
    const vc_json_size = Buffer.byteLength(JSON.stringify(vc), 'utf8');
    total_vc_size += vc_json_size;
}
// VP creation
const vp = await createPresentation(credentials, holder.did);
const vp_size = Buffer.byteLength(JSON.stringify(vp), 'utf8');
// Final map
const sizes = {
    'Total VC Payloads': total_vc_size,
    'Final VP': vp_size,
};
console.log(`Message Size Breakdown for ${n_issuers} issuers (N VC issued):`);
console.table(sizes);
const csvLines = Object.entries(sizes).map(([label, size]) => `${n_issuers},${label},${size}`);
fs.appendFileSync(SIZE_CSV, csvLines.join('\n') + '\n');
console.log(`Results appended to ${SIZE_CSV}`);
await cleanup();
