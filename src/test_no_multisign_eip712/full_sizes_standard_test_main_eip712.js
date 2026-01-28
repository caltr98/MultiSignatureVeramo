import { cleanup, setup_agents } from './enviroment_setup.js';
import { generateVCPayload } from './generate_VC_payload.js';
import { agent } from '../veramo/setup_eip712.js';
import fs from 'fs';
import path from 'path';
import { createPresentation } from './holder_test.js';
import { fileURLToPath } from 'url';
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
const RESULTS_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..', 'experimental_results');
fs.mkdirSync(RESULTS_DIR, { recursive: true });
const SIZE_CSV = path.join(RESULTS_DIR, `message_sizes_standard_eip712_claims${claims_n}_size${claims_size}.csv`);
if (!fs.existsSync(SIZE_CSV)) {
    fs.writeFileSync(SIZE_CSV, 'Issuers,StepName,Size_bytes\n');
}
const issuers = await setup_agents(n_issuers);
const holder = (await setup_agents(1))[0];
const credentials = [];
let total_vc_size = 0;
for (const issuer of issuers) {
    const payload = await generateVCPayload(holder.did, claims_n, claims_size, 42);
    const vc = await agent.createVerifiableCredentialEIP712({
        credential: {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            type: ['VerifiableCredential'],
            issuer: { id: issuer.did },
            credentialSubject: payload.credentialSubject,
        },
        keyRef: issuer.keyRef,
    });
    credentials.push(vc);
    total_vc_size += Buffer.byteLength(JSON.stringify(vc), 'utf8');
}
const vp = await createPresentation(credentials, holder.did, holder.keyRef);
const vp_size = Buffer.byteLength(JSON.stringify(vp), 'utf8');
const sizes = {
    'Total VC Payloads': total_vc_size,
    'Final VP': vp_size,
};
console.log(`Message Size Breakdown for ${n_issuers} issuers (N EIP712 VC issued):`);
console.table(sizes);
const csvLines = Object.entries(sizes).map(([label, size]) => `${n_issuers},${label},${size}`);
fs.appendFileSync(SIZE_CSV, csvLines.join('\n') + '\n');
console.log(`Results appended to ${SIZE_CSV}`);
await cleanup();
