import { agent } from './veramo/setup.js'
import { computeAddress, Wallet } from 'ethers'
import {ICreateVerifiableCredentialArgs} from "@veramo/core-types";

async function main() {
    let identifier;

// 1. Dati noti
    const privKeyHex = 'e46235123903a241476a6bba96dca5cfd0728f2212e6b602ce9d9ce075dcde5a'
    const address = "0x0B975Efc6C4Ab5D3CBd3e8b94BE1a248c857f8e8"

// 2. Usa chiave già creata
    //NOTE: YOU MUST CHANGE IT EVERYTIME YOU CREATE A NEW KEY AND YOU MUST RECOMPILE THE CODE
    const kidAlreadyCreated = "954393b2c6d7ffb9f0dde4b8cfa34b331c6db36335e01010ad94c4d00f8db9d770cc5bda184d7813851beb415e92b1c6"

    const vc = await agent.createVerifiableCredential({
        credential: {
            issuer: { id: `did:ethr:sepolia:${address}` },
            credentialSubject: {
                id: 'did:web:example.com:alice',
                name: 'Alice',
            },
            issuanceDate: new Date().toISOString(),
            type: ['VerifiableCredential'],
            context: ['https://www.w3.org/2018/credentials/v1'],
        },
        proofFormat: 'bls',
        keyRef: kidAlreadyCreated, // Force usage of BLS key!
        //Calling with ProofFormat Bls, requires the next statement!
    } as ICreateVerifiableCredentialArgs & { proofFormat: 'bls' });



    console.log("VC CREATED"+JSON.stringify(vc,null,2))
    const result = await agent.verifyCredential({
        credential: {
            "credentialSubject": vc.credentialSubject,
            "issuer":vc.issuer,
            "type": [
                "VerifiableCredential"
            ],
            "@context": [
                "https://www.w3.org/2018/credentials/v1"
            ],
            "issuanceDate": vc.issuanceDate,
            "proof": vc.proof
        }
    })
    console.log(`Credential verified`, result.verified)


}

main().catch(console.log)