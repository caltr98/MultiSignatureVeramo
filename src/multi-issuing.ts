//NEW ALL: LOGIC FOR BLS Multisignature ISSUING

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


    const vc1 = await agent.signMultiIssuedVerifiableCredential({
        credential: {
            issuer: { id :`did:ethr:sepolia:${address}` },
            multi_issuers: [`did:ethr:sepolia:${address}`, `did:ethr:sepolia:${address}`] ,
            credentialSubject: {
                id: 'did:web:example.com:alice',
                name: 'Alice',
            },
            type: ['Sign_MultiSign_VerifiableCredential']
        },
        proofFormat: 'sign-bls-multi-signature',
        keyRef: kidAlreadyCreated, // Force usage of BLS key!
        //Calling with ProofFormat Bls, requires the next statement!
    } as ICreateVerifiableCredentialArgs & { proofFormat: 'sign-bls-multi-signature' });

    const vc2 = await agent.signMultiIssuedVerifiableCredential({
        credential: {
            issuer: { id :`did:ethr:sepolia:${address}` },
            multi_issuers: [`did:ethr:sepolia:${address}`, `did:ethr:sepolia:${address}`] ,
            credentialSubject: {
                id: 'did:web:example.com:alice',
                name: 'Alice',
            },
            type: ['Sign_MultiSign_VerifiableCredential'],
        },
        proofFormat: 'sign-bls-multi-signature',
        keyRef: kidAlreadyCreated, // Force usage of BLS key!
        //Calling with ProofFormat Bls, requires the next statement!
    } as ICreateVerifiableCredentialArgs & { proofFormat: 'sign-bls-multi-signature' });

    console.log("VC1:", vc1)
    console.log("VC2:", vc2)

    const vc3 = await agent.createMultiIssuerVerifiableCredential({
        credential: {
            issuer: { id :`did:ethr:sepolia:${address}` },
            multi_issuers: [`did:ethr:sepolia:${address}`, `did:ethr:sepolia:${address}`] ,
            credentialSubject: {
                id: 'did:web:example.com:alice',
                name: 'Alice',
            },
            type: ['Sign_MultiSign_VerifiableCredential'],
        },
        proofFormat: 'aggregate-bls-multi-signature',
        keyRef: kidAlreadyCreated, // Force usage of BLS key!
        signatures: [vc1.signatureData.signatureHex, vc2.signatureData.signatureHex]
        //Calling with ProofFormat Bls, requires the next statement!
    } as ICreateVerifiableCredentialArgs & { proofFormat: 'aggregate-bls-multi-signature' });

    //console.log(vc3)


}

main().catch(console.log)