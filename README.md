## Veramo Extended for Multisignature


Structure is as follows:
* plugins/veramo-plugin-multisig: The extension of veramo agent-plugin that allows for creating and verifying multisignature credentials.
* bls.extend-credential-w3c.ts: A modified version of the W3C credential veramo plugin that allows for multisignature support using bls.
* did-provider.ts: A modified version of the did-provider plugin that allows for support for bls keys, allowing to publish bls public keys on the DID Doc
* kms-local-bls: extension of the kms-local plugin that allows for using bls keys for encryption and decryption, adding those cryptographic capabilities to veramo agents

# Testing mains
To test the multisignature functionality, you can use the following scripts:
* Concerto-BLS: A sample of BLS following the model with a leader that aggregates the signatures with bls key and public bls keys and puts them on a VC
* create-did-with-bls-key.ts: A script that creates a DID with a bls key and publishes it on the DID Doc on Sepolia
* create_key_key.ts: creates a bls key and a bls key pair and stores the private key, its needed to be executed before the above script
* create-vc-then-verify.ts: creates a VC with a bls signature and verifies it with the a BLS key and recovers from Sepolia the public key to then verify the signature
* multisig-vc-creation.ts: creates a multisig VC with a bls signature and verifies it with the a BLS key and recovers from Sepolia the public keys to then verify the aggregated BLS signature
* signature-with-bls.ts: signs a simple message with a bls key

# Usage
* npx tsc --resolveJsonModule to compile the typescript files to js files.
* yarn ts-node --esm ./src/script.js 

