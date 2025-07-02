import { agent } from './veramo/setup.js';
async function main() {
    const dummyKey = await agent.keyManagerCreate({ kms: 'local', type: 'Bls12381G1' });
    console.log(`New dummy key created`);
    console.log(JSON.stringify(dummyKey, null, 2));
}
main().catch(console.log);
