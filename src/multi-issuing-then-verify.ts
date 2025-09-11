//NEW ALL: LOGIC FOR BLS Multisignature ISSUING

import { agent } from './veramo/setup.js'
import { computeAddress, Wallet } from 'ethers'
import {ICreateVerifiableCredentialArgs} from "@veramo/core-types";
import bls from "@chainsafe/bls";
import {ISignMultiIssuerVerifiableCredentialArgs} from "./plugins/bls-extend-credential-w3c/src/action-handler";

async function main() {
    let identifier;

// 1. Dati noti
    const privKeyHex = 'e46235123903a241476a6bba96dca5cfd0728f2212e6b602ce9d9ce075dcde5a'
    const address = "0x03A7C4B3126E57bABe1206090C52F4070A9b381e"
    const privKeyHex2 = '423c950596abae910e6bc845859ba561b1977cffae4174f2c9c40596c2903261'
    const address2 = "0xc97F8bEb6A5abE8a1dA85AF4649f2eB356194fed"

// 2. Usa chiave già creata
    //NOTE: YOU MUST CHANGE IT EVERYTIME YOU CREATE A NEW KEY AND YOU MUST RECOMPILE THE CODE
    const kidAlreadyCreated = "a4a5fc45f76e61bba338a856bd2a9c0ca353e6dfbb7b97345022ad4bcb561a7df50fe53817cd11fdfc2083808ca92576"

    const kidAlreadyCreated2 = "8caebe37bcc2b1ac81687c97daa7c5510ba6f01fdcab8a4a267fcda8699ddc54fe7de40fbbe007a689e1da866356550f"



    const payloadToSign = {
        multi_issuers: [`did:ethr:sepolia:${address}`, `did:ethr:sepolia:${address2}`] ,
        credentialSubject: {
            id: 'did:web:example.com:alice',
            name: 'Alice',
        },
        type: [
            "VerifiableCredential", "Sign_MultiSign_VerifiableCredential"
        ]
    }

    //console.log("step1")
    const vc1 = await agent.signMultiIssuedVerifiableCredential({
        credential: payloadToSign,
        issuer:`did:ethr:sepolia:${address}`,
        proofFormat: 'sign-bls-multi-signature',
        keyRef: kidAlreadyCreated, // Force usage of BLS key!
        //Calling with ProofFormat Bls, requires the next statement!
    } as ISignMultiIssuerVerifiableCredentialArgs & { proofFormat: 'sign-bls-multi-signature' });

    const vc2 = await agent.signMultiIssuedVerifiableCredential({
        credential: payloadToSign,
        issuer:`did:ethr:sepolia:${address2}`,
        proofFormat: 'sign-bls-multi-signature',
        keyRef: kidAlreadyCreated2, // Force usage of BLS key!
        //Calling with ProofFormat Bls, requires the next statement!
    } as ISignMultiIssuerVerifiableCredentialArgs & { proofFormat: 'sign-bls-multi-signature' });

    //console.log("VC1"+JSON.stringify(vc1,null,2))

    let list_of_signatures = [vc1.signatureData.signatureHex, vc2.signatureData.signatureHex]
    // converti le firme da stringhe esadecimali a oggetti Signature
        const signatureObjs = list_of_signatures.map(sigHex => bls.Signature.fromHex(sigHex))

    // aggrega le firme
    const aggregatedSignature = bls.aggregateSignatures(signatureObjs)
    const signaturesAggregatedHex = Buffer.from(aggregatedSignature).toString('hex')


    let publicKey1 = bls.PublicKey.fromBytes(Buffer.from("a4a5fc45f76e61bba338a856bd2a9c0ca353e6dfbb7b97345022ad4bcb561a7df50fe53817cd11fdfc2083808ca92576", 'hex'))
    let publicKey2 = bls.PublicKey.fromBytes(Buffer.from("8caebe37bcc2b1ac81687c97daa7c5510ba6f01fdcab8a4a267fcda8699ddc54fe7de40fbbe007a689e1da866356550f", 'hex'))



    const vc3 = await agent.createMultiIssuerVerifiableCredential({
        credential: payloadToSign,
        issuer: { id :`did:ethr:sepolia:${address}` },
        proofFormat: 'aggregate-bls-multi-signature',
        keyRef: kidAlreadyCreated, // Force usage of BLS key!
        signatures: [vc1.signatureData.signatureHex, vc2.signatureData.signatureHex]
        //Calling with ProofFormat Bls, requires the next statement!
    } as ICreateVerifiableCredentialArgs & { proofFormat: 'aggregate-bls-multi-signature' });


    //console.log(vc3)
    //console.log("VC CREATED 3"+JSON.stringify(vc3,null,2))
    const result = await agent.verifyMultisignatureCredential({
        credential: {
            "credentialSubject": vc3.credentialSubject,
            "multi_issuers":vc3.multi_issuers,
            "type": [
                "VerifiableCredential", "Sign_MultiSign_VerifiableCredential"
            ],
            "@context": [
                "https://www.w3.org/2018/credentials/v1"
            ],
            "proof": vc3.proof
        }
    })
    //console.log(`Credential verified`, result.verified)


}

main().catch(console.log)