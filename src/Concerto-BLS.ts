//NEW ALL: LOGIC FOR BLS Multisignature ISSUING

import { agent } from './veramo/setup.js'
import { sha256 } from '@noble/hashes/sha256'


import { computeAddress, Wallet } from 'ethers'
import {ICreateVerifiableCredentialArgs, MinimalImportableKey} from "@veramo/core-types";
import bls from "@chainsafe/bls";
import {
    ICreateProofOfOwnershipMultiIssuerVerifiableCredentialArgs,
    ISignMultiIssuerVerifiableCredentialArgs
} from "./plugins/bls-extend-credential-w3c/src/action-handler";
import canonicalize from "canonicalize";

async function main() {
    let identifier;

// 1. Dati noti
    const privKeyHex = '5e9c48b3b8f10589adac746ea63b63dfcbd4708ff032fd0dcc9c7c1aa045a53c'
    const address = "0x03A7C4B3126E57bABe1206090C52F4070A9b381e"
    const privKeyHex2 = '423c950596abae910e6bc845859ba561b1977cffae4174f2c9c40596c2903261'
    const address2 = "0xc97F8bEb6A5abE8a1dA85AF4649f2eB356194fed"

// 2. Usa chiave già creata
    //NOTE: YOU MUST CHANGE IT EVERYTIME YOU CREATE A NEW KEY AND YOU MUST RECOMPILE THE CODE
    const kidAlreadyCreated = "a4a5fc45f76e61bba338a856bd2a9c0ca353e6dfbb7b97345022ad4bcb561a7df50fe53817cd11fdfc2083808ca92576"

    const kidAlreadyCreated2 = "8caebe37bcc2b1ac81687c97daa7c5510ba6f01fdcab8a4a267fcda8699ddc54fe7de40fbbe007a689e1da866356550f"


    //3 Aggregazione delle keys
    let publicKey13 = bls.PublicKey.fromBytes(Buffer.from("a4a5fc45f76e61bba338a856bd2a9c0ca353e6dfbb7b97345022ad4bcb561a7df50fe53817cd11fdfc2083808ca92576", 'hex'))
    let publicKey23 = bls.PublicKey.fromBytes(Buffer.from("8caebe37bcc2b1ac81687c97daa7c5510ba6f01fdcab8a4a267fcda8699ddc54fe7de40fbbe007a689e1da866356550f", 'hex'))


    let aggregatedKey = await agent.aggregateBlsPublicKeys({
        list_of_publicKeyHex: ["a4a5fc45f76e61bba338a856bd2a9c0ca353e6dfbb7b97345022ad4bcb561a7df50fe53817cd11fdfc2083808ca92576",
            "8caebe37bcc2b1ac81687c97daa7c5510ba6f01fdcab8a4a267fcda8699ddc54fe7de40fbbe007a689e1da866356550f"
        ]
    })






    const payloadToSign = {
        '@context': ["https://www.w3.org/2018/credentials/v1"],
        multi_issuers: [`did:ethr:sepolia:${address}`, `did:ethr:sepolia:${address2}`] ,
            credentialSubject: {
                id: 'did:web:example.com:alice',
                name: 'Alice',
            },
            type: ['VerifiableCredential','aggregated-bls-multi-signature'],
            aggregated_bls_public_key: aggregatedKey.bls_aggregated_pubkey,
    }


    //Phase of Combining Signatures
    //Generate Proof of Ownership

    //const proofOfOwnershipPayload = aggregatedKey +""+payloadToSign

    //temporary easy way!
    const proofOfOwnershipPayload =  JSON.stringify(payloadToSign)

    /*args required
    keyRef: string  -> must be a keyRef to a ETH key
    algorithm?: string    .>ECDSA
    data: string
    encoding?: "utf-8" | "base16" | "base64" | "hex"
    [p: string]: any
     */

    const keyETH1:MinimalImportableKey = {
        type: 'Secp256k1',
        privateKeyHex: privKeyHex,
        kms: 'local'
    };
    const keyETH2:MinimalImportableKey = {
        type: 'Secp256k1',
        privateKeyHex: privKeyHex2,
        kms: 'local'
    };


    const kidETH1 = await agent.keyManagerImport(keyETH1);
    const kidETH2 = await agent.keyManagerImport(keyETH2);

    //ECDSA over secp256k1, with Ethereum's message prefix
    const PoO1 = await agent.keyManagerSign({keyRef: kidETH1.kid, data: proofOfOwnershipPayload,
    algorithm : "eth_signMessage", encoding: "utf-8" })

    const PoO2 = await agent.keyManagerSign({keyRef: kidETH2.kid, data: proofOfOwnershipPayload,
        algorithm : "eth_signMessage", encoding: "utf-8" })

    console.log("signature when made" + PoO1)



    const signature1 = await agent.signMultiIssuedVerifiableCredential({
        credential: payloadToSign,
        issuer:`did:ethr:sepolia:${address}`,
        proofFormat: 'sign-bls-multi-signature',
        keyRef: kidAlreadyCreated, // Force usage of BLS key!
        //Calling with ProofFormat Bls, requires the next statement!
    } as ISignMultiIssuerVerifiableCredentialArgs & { proofFormat: 'sign-bls-multi-signature' });

    const signature2 = await agent.signMultiIssuedVerifiableCredential({
        credential: payloadToSign,
        issuer:`did:ethr:sepolia:${address2}`,
        proofFormat: 'sign-bls-multi-signature',
        keyRef: kidAlreadyCreated2, // Force usage of BLS key!
        //Calling with ProofFormat Bls, requires the next statement!
    } as ISignMultiIssuerVerifiableCredentialArgs & { proofFormat: 'sign-bls-multi-signature' });




    let list_of_signatures = [signature1.signatureData.signatureHex, signature2.signatureData.signatureHex]
    // converti le firme da stringhe esadecimali a oggetti Signature
    const signatureObjs = list_of_signatures.map(sigHex => bls.Signature.fromHex(sigHex))

    // aggrega le firme
    const aggregatedSignature = bls.aggregateSignatures(signatureObjs)
    const signaturesAggregatedHex = Buffer.from(aggregatedSignature).toString('hex')


    console.log("structure of signature"+JSON.stringify(signature2,null,2))

    const verificationResult = bls.verifyAggregate([publicKey13, publicKey23], Uint8Array.from(Buffer.from(payloadToSign.toString(), 'utf-8')), aggregatedSignature);


    //let publicKey1 = bls.PublicKey.fromBytes(Buffer.from("a4a5fc45f76e61bba338a856bd2a9c0ca353e6dfbb7b97345022ad4bcb561a7df50fe53817cd11fdfc2083808ca92576\n", 'hex'))
    //let publicKey2 = bls.PublicKey.fromBytes(Buffer.from("8caebe37bcc2b1ac81687c97daa7c5510ba6f01fdcab8a4a267fcda8699ddc54fe7de40fbbe007a689e1da866356550f\n\n", 'hex'))





    /*
    const vcFull = await agent.createMultiIssuerVerifiableCredential({
        credential: payloadToSign,
        issuer: { id :`did:ethr:sepolia:${address}` },
        proofFormat: 'aggregate-bls-multi-signature',
        keyRef: kidAlreadyCreated, // Force usage of BLS key!
        signatures: [signature1.signatureData.signatureHex, signature2.signatureData.signatureHex]
        //Calling with ProofFormat Bls, requires the next statement!
    } as ICreateVerifiableCredentialArgs & { proofFormat: 'aggregate-bls-multi-signature' });
*/
    const vcFull = await agent.createProofOfOwnershipMultiIssuerVerifiableCredential({
        credential: payloadToSign,
        proofData: {
            "signatures": [signature1.signatureData.signatureHex, signature2.signatureData.signatureHex],
            "publicKey": aggregatedKey.bls_aggregated_pubkey
        },
        type: ['Sign_MultiSign_VerifiableCredential'],
        proofsOfOwnership: [PoO1, PoO2],
        proofFormat: 'ProofOfOwnership-aggregate-bls-multi-signature',
        signatures: [signature1.signatureData.signatureHex, signature2.signatureData.signatureHex]
    } as ICreateProofOfOwnershipMultiIssuerVerifiableCredentialArgs & { proofFormat: 'ProofOfOwnership-aggregate-bls-multi-signature' });


    console.log("VC FULL"+JSON.stringify(vcFull,null,2))

    const result = await agent.verifyProofOfOwnershipMultisignatureCredential({
        credential: {
            "credentialSubject": vcFull.credentialSubject,
            "multi_issuers":vcFull.multi_issuers,
            "type": [
                "VerifiableCredential", "aggregated-bls-multi-signature"
            ],
            "@context": [
                "https://www.w3.org/2018/credentials/v1"
            ],
            "proof": vcFull.proof,
            aggregated_bls_public_key: aggregatedKey.bls_aggregated_pubkey,

        }
    })
    console.log(`Credential verified`, result.verified)

}

main().catch(console.log)