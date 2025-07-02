import { agent } from './veramo/setup.js';
async function main() {
    const dummyKey = await agent.keyManagerCreate({ kms: 'local', type: 'Bls12381G1' });
    //make a single signature
    const signature = await agent.keyManagerSign({ kms: 'local', keyRef: dummyKey.kid, algorithm: "single-signature", data: 'Hello, world!' });
    console.log(`Signature created with dummy key ${dummyKey.kid}: ${signature}`);
    console.log(JSON.stringify(signature, null, 2));
}
main().catch(console.log);
