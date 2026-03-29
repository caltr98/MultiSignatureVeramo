//NEW:CHANGED TO CREATE BLS KEY
//NEW:CHANGED Import key as you must account for bls
// NEW: NEED TO CHANGE asManagedKeyInfo TO ACCOUNT FOR BLS
//TODO: ADD BLS SIGNATURE
//TODO: Key_Alg_Mapping needs to be updated to account for BLS
import { KEY_ALG_MAPPING, } from '@veramo/core-types';
import { AbstractKeyManagementSystem, } from '@veramo/key-manager';
import { EdDSASigner, ES256KSigner, ES256Signer } from 'did-jwt';
import { ed25519, x25519 } from '@noble/curves/ed25519';
import { p256 } from '@noble/curves/p256';
import { toUtf8String, Wallet, SigningKey, randomBytes, getBytes, hexlify, Transaction } from 'ethers';
//import //debug from '//debug'
import { bytesToHex, concat, convertEd25519PrivateKeyToX25519, convertEd25519PublicKeyToX25519, hexToBytes, } from '@veramo/utils';
function resolveBlsBackend(value) {
    return value === 'noble' ? 'noble' : 'chainsafe';
}
function readEnv(name) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const p = typeof process !== 'undefined' ? process : undefined;
    return p?.env?.[name];
}
function strip0x(hex) {
    return hex.startsWith('0x') ? hex.slice(2) : hex;
}
/**
 * This is an implementation of {@link @veramo/key-manager#AbstractKeyManagementSystem | AbstractKeyManagementSystem}
 * that uses a local {@link @veramo/key-manager#AbstractPrivateKeyStore | AbstractPrivateKeyStore} to hold private key
 * material.
 *
 * The key material is used to provide local implementations of various cryptographic algorithms.
 *
 * @public
 */
export class BlsKeyManagementSystem extends AbstractKeyManagementSystem {
    keyStore;
    blsBackend;
    chainsafeBlsPromise;
    nobleBlsPromise;
    constructor(keyStore, options) {
        super();
        this.keyStore = keyStore;
        this.blsBackend = options?.blsBackend ?? resolveBlsBackend(readEnv('VERAMO_BLS_BACKEND'));
    }
    async importKey(args) {
        if (!args.type || !args.privateKeyHex) {
            throw new Error('invalid_argument: type and privateKeyHex are required to import a key');
        }
        const managedKey = await this.asManagedKeyInfo({ alias: args.kid, ...args });
        await this.keyStore.importKey({ alias: managedKey.kid, ...args });
        //debug('imported key', managedKey.type, managedKey.publicKeyHex)
        return managedKey;
    }
    async listKeys() {
        const privateKeys = await this.keyStore.listKeys({});
        const managedKeys = await Promise.all(privateKeys.map((key) => this.asManagedKeyInfo(key)));
        return managedKeys;
    }
    async createKey({ type }) {
        let key;
        switch (type) {
            case 'Ed25519': {
                const ed25519SecretKey = ed25519.utils.randomPrivateKey();
                const publicKey = ed25519.utils.getExtendedPublicKey(ed25519SecretKey).pointBytes;
                key = await this.importKey({
                    type,
                    privateKeyHex: bytesToHex(concat([ed25519SecretKey, publicKey])),
                });
                break;
            }
            case 'Secp256r1': // Generation uses exactly the same input mechanism for both Secp256k1 and Secp256r1
            case 'Secp256k1': {
                const privateBytes = randomBytes(32);
                key = await this.importKey({
                    type,
                    privateKeyHex: bytesToHex(privateBytes),
                });
                break;
            }
            case 'X25519': {
                const secretX25519 = x25519.utils.randomPrivateKey();
                key = await this.importKey({
                    type,
                    privateKeyHex: bytesToHex(secretX25519),
                });
                break;
            }
            case "Bls12381G1": {
                if (this.blsBackend === 'noble') {
                    const bls = await this.getNobleBls();
                    const secretKeyBytes = bls.utils.randomPrivateKey();
                    key = await this.importKey({
                        type,
                        privateKeyHex: bytesToHex(secretKeyBytes),
                    });
                }
                else {
                    const bls = await this.getChainsafeBls();
                    const secretKey = bls.SecretKey.fromKeygen();
                    key = await this.importKey({
                        type,
                        privateKeyHex: bytesToHex(secretKey.toBytes()),
                    });
                }
                break;
            }
            default:
                throw Error('not_supported: Key type not supported: ' + type);
        }
        //debug('Created key', type, key.publicKeyHex)
        return key;
    }
    async deleteKey(args) {
        return await this.keyStore.deleteKey({ alias: args.kid });
    }
    async sign({ keyRef, algorithm, data, }) {
        let managedKey;
        try {
            managedKey = await this.keyStore.getKey({ alias: keyRef.kid });
        }
        catch (e) {
            throw new Error(`key_not_found: No key entry found for kid=${keyRef.kid}`);
        }
        //define NEW behavior for BLS
        if (managedKey.type === 'Bls12381G1') {
            if (algorithm === "BLS_SIGNATURE") {
                return await this.signBls(managedKey.privateKeyHex, data);
            }
            if (algorithm === "BLS_AGGREGATE_MULTI_SIGNATURE") {
                return await this.aggregateBls(managedKey.privateKeyHex, data);
            }
        }
        if (managedKey.type === 'Ed25519' &&
            (typeof algorithm === 'undefined' || ['Ed25519', 'EdDSA'].includes(algorithm))) {
            return await this.signEdDSA(managedKey.privateKeyHex, data);
        }
        else if (managedKey.type === 'Secp256k1') {
            if (typeof algorithm === 'undefined' || ['ES256K', 'ES256K-R'].includes(algorithm)) {
                return await this.signES256K(managedKey.privateKeyHex, algorithm, data);
            }
            else if (['eth_signTransaction', 'signTransaction', 'signTx'].includes(algorithm)) {
                return await this.eth_signTransaction(managedKey.privateKeyHex, data);
            }
            else if (algorithm === 'eth_signMessage') {
                return await this.eth_signMessage(managedKey.privateKeyHex, data);
            }
            else if (['eth_signTypedData', 'EthereumEip712Signature2021'].includes(algorithm)) {
                return await this.eth_signTypedData(managedKey.privateKeyHex, data);
            }
            else if (['eth_rawSign'].includes(algorithm)) {
                return this.eth_rawSign(managedKey.privateKeyHex, data);
            }
        }
        else if (managedKey.type === 'Secp256r1' &&
            (typeof algorithm === 'undefined' || algorithm === 'ES256')) {
            return await this.signES256(managedKey.privateKeyHex, data);
        }
        throw Error(`not_supported: Cannot sign ${algorithm} using key of type ${managedKey.type}`);
    }
    async sharedSecret(args) {
        let myKey;
        try {
            myKey = await this.keyStore.getKey({ alias: args.myKeyRef.kid });
        }
        catch (e) {
            throw new Error(`key_not_found: No key entry found for kid=${args.myKeyRef.kid}`);
        }
        if (!myKey.privateKeyHex) {
            throw Error('key_not_managed: No private key is available for kid: ' + myKey.alias);
        }
        let theirKey = args.theirKey;
        if (!theirKey.type ||
            typeof theirKey.type !== 'string' ||
            !theirKey.publicKeyHex ||
            typeof theirKey.publicKeyHex !== 'string') {
            throw new Error(`invalid_argument: args.theirKey must contain 'type' and 'publicKeyHex'`);
        }
        let myKeyBytes = getBytes('0x' + myKey.privateKeyHex);
        if (myKey.type === 'Ed25519') {
            myKeyBytes = convertEd25519PrivateKeyToX25519(myKeyBytes);
        }
        else if (myKey.type !== 'X25519') {
            throw new Error(`not_supported: can't compute shared secret for type=${myKey.type}`);
        }
        let theirKeyBytes = getBytes('0x' + theirKey.publicKeyHex);
        if (theirKey.type === 'Ed25519') {
            theirKeyBytes = convertEd25519PublicKeyToX25519(theirKeyBytes);
        }
        else if (theirKey.type !== 'X25519') {
            throw new Error(`not_supported: can't compute shared secret for type=${theirKey.type}`);
        }
        const shared = x25519.getSharedSecret(myKeyBytes, theirKeyBytes);
        return hexlify(shared).substring(2);
    }
    /**
     * @returns a `0x` prefixed hex string representing the signed EIP712 data
     */
    async eth_signTypedData(privateKeyHex, data) {
        let msg, msgDomain, msgTypes;
        const serializedData = toUtf8String(data);
        try {
            let jsonData = JSON.parse(serializedData);
            if (typeof jsonData.domain === 'object' && typeof jsonData.types === 'object') {
                const { domain, types, message } = jsonData;
                msg = message;
                msgDomain = domain;
                msgTypes = types;
            }
            else {
                // next check will throw since the data couldn't be parsed
            }
        }
        catch (e) {
            // next check will throw since the data couldn't be parsed
        }
        if (typeof msgDomain !== 'object' || typeof msgTypes !== 'object' || typeof msg !== 'object') {
            throw Error(`invalid_arguments: Cannot sign typed data. 'domain', 'types', and 'message' must be provided`);
        }
        delete msgTypes.EIP712Domain;
        const wallet = new Wallet(privateKeyHex);
        const signature = await wallet.signTypedData(msgDomain, msgTypes, msg);
        // HEX encoded string
        return signature;
    }
    /**
     * @returns a `0x` prefixed hex string representing the signed message
     */
    async eth_signMessage(privateKeyHex, rawMessageBytes) {
        const wallet = new Wallet(privateKeyHex);
        const signature = await wallet.signMessage(rawMessageBytes);
        // HEX encoded string, 0x prefixed
        return signature;
    }
    /**
     * @returns a `0x` prefixed hex string representing the signed raw transaction
     */
    async eth_signTransaction(privateKeyHex, rlpTransaction) {
        const transaction = Transaction.from(bytesToHex(rlpTransaction, true));
        const wallet = new Wallet(privateKeyHex);
        if (transaction.from) {
            //debug('WARNING: executing a transaction signing request with a `from` field.')
            if (wallet.address.toLowerCase() !== transaction.from.toLowerCase()) {
                const msg = 'invalid_arguments: eth_signTransaction `from` field does not match the chosen key. `from` field should be omitted.';
                //debug(msg)
                throw new Error(msg);
            }
        }
        const signedRawTransaction = await wallet.signTransaction(transaction);
        // HEX encoded string, 0x prefixed
        return signedRawTransaction;
    }
    /**
     * @returns a `0x` prefixed hex string representing the signed digest in compact format
     */
    eth_rawSign(managedKey, data) {
        return new SigningKey('0x' + managedKey).sign(data).compactSerialized;
    }
    /**
     * @returns a base64url encoded signature for the `EdDSA` alg
     */
    async signEdDSA(key, data) {
        const signer = EdDSASigner(hexToBytes(key));
        const signature = await signer(data);
        // base64url encoded string
        return signature;
    }
    /**
     * @returns a base64url encoded signature for the `ES256K` or `ES256K-R` alg
     */
    async signES256K(privateKeyHex, alg, data) {
        const signer = ES256KSigner(hexToBytes(privateKeyHex), alg === 'ES256K-R');
        const signature = await signer(data);
        // base64url encoded string
        return signature;
    }
    /**
     * @returns a base64url encoded signature for the `ES256` alg
     */
    async signES256(privateKeyHex, data) {
        const signer = ES256Signer(hexToBytes(privateKeyHex));
        const signature = await signer(data);
        // base64url encoded string
        return signature;
    }
    /**
     * Converts a {@link @veramo/key-manager#ManagedPrivateKey | ManagedPrivateKey} to
     * {@link @veramo/core-types#ManagedKeyInfo}
     */
    async asManagedKeyInfo(args) {
        let key;
        switch (args.type) {
            case 'Ed25519': {
                const secretKey = hexToBytes(args.privateKeyHex.toLowerCase());
                const publicKeyHex = bytesToHex(ed25519.getPublicKey(secretKey.subarray(0, 32)));
                key = {
                    type: args.type,
                    kid: args.alias || publicKeyHex,
                    publicKeyHex,
                    meta: {
                        algorithms: [...KEY_ALG_MAPPING[args.type], 'Ed25519'],
                    },
                };
                break;
            }
            case 'Secp256k1': {
                const privateBytes = hexToBytes(args.privateKeyHex.toLowerCase());
                const keyPair = new SigningKey(privateBytes);
                const publicKeyHex = keyPair.publicKey.substring(2);
                key = {
                    type: args.type,
                    kid: args.alias || publicKeyHex,
                    publicKeyHex,
                    meta: {
                        algorithms: [
                            ...KEY_ALG_MAPPING[args.type],
                            'eth_signTransaction',
                            'eth_signTypedData',
                            'eth_signMessage',
                            'eth_rawSign',
                        ],
                    },
                };
                break;
            }
            case 'Secp256r1': {
                const privateBytes = hexToBytes(args.privateKeyHex.toLowerCase());
                const publicKeyHex = bytesToHex(p256.getPublicKey(privateBytes, true));
                key = {
                    type: args.type,
                    kid: args.alias || publicKeyHex,
                    publicKeyHex,
                    meta: {
                        algorithms: ['ES256'], // ECDH not supported yet by this KMS
                    },
                };
                break;
            }
            case 'X25519': {
                const secretKeyBytes = hexToBytes(args.privateKeyHex.toLowerCase());
                const publicKeyHex = bytesToHex(x25519.getPublicKey(secretKeyBytes));
                key = {
                    type: args.type,
                    kid: args.alias || publicKeyHex,
                    publicKeyHex: publicKeyHex,
                    meta: {
                        algorithms: [...KEY_ALG_MAPPING[args.type]],
                    },
                };
                break;
            }
            case 'Bls12381G1': {
                const publicKeyHex = await this.deriveBlsPublicKeyHex(args.privateKeyHex.toLowerCase());
                key = {
                    type: args.type,
                    kid: args.alias || publicKeyHex,
                    publicKeyHex: publicKeyHex,
                    meta: {
                        algorithms: ['BLS_SIGNATURE', 'BLS_AGGREGATE_MULTI_SIGNATURE'],
                    },
                };
                break;
            }
            default:
                throw Error('not_supported: Key type not supported: ' + args.type);
        }
        return key;
    }
    //NEW: BLS SIGNATURE function
    async signBls(privateKeyHex, data) {
        const secretKeyBytes = hexToBytes(strip0x(privateKeyHex));
        if (this.blsBackend === 'noble') {
            const bls = await this.getNobleBls();
            const signatureBytes = bls.sign(data, secretKeyBytes);
            return bytesToHex(signatureBytes);
        }
        else {
            const bls = await this.getChainsafeBls();
            const secretKey = bls.SecretKey.fromBytes(secretKeyBytes);
            const signature = secretKey.sign(data);
            const signatureBytes = typeof signature?.toBytes === 'function' ? signature.toBytes() : signature;
            return bytesToHex(signatureBytes);
        }
    }
    //new: BLS AGGREGATE MULTI-SIGNATURE function
    async aggregateBls(privateKeyHex, data) {
        let parsed;
        // Parse the data as JSON, as the data are the stringified signatures
        try {
            const jsonString = new TextDecoder().decode(data);
            parsed = JSON.parse(jsonString);
        }
        catch (e) {
            throw new Error('invalid_argument: Expected data to be a JSON-encoded object with "signatures"');
        }
        if (!Array.isArray(parsed.signatures)) {
            throw new Error('invalid_argument: "signatures" field must be a non-empty array');
        }
        if (this.blsBackend === 'noble') {
            const bls = await this.getNobleBls();
            const signatures = parsed.signatures.map((hex) => hexToBytes(strip0x(hex)));
            const aggregated = bls.aggregateSignatures(signatures);
            return bytesToHex(aggregated);
        }
        else {
            const bls = await this.getChainsafeBls();
            const signatures = parsed.signatures.map((hex) => bls.Signature.fromHex(strip0x(hex)));
            const aggregated = bls.aggregateSignatures(signatures);
            const aggregatedBytes = typeof aggregated?.toBytes === 'function' ? aggregated.toBytes() : aggregated;
            return bytesToHex(aggregatedBytes);
        }
    }
    async deriveBlsPublicKeyHex(privateKeyHex) {
        const secretKeyBytes = hexToBytes(strip0x(privateKeyHex));
        if (this.blsBackend === 'noble') {
            const bls = await this.getNobleBls();
            const publicKeyBytes = bls.getPublicKey(secretKeyBytes);
            return bytesToHex(publicKeyBytes);
        }
        else {
            const bls = await this.getChainsafeBls();
            const secretKey = bls.SecretKey.fromBytes(secretKeyBytes);
            const publicKey = secretKey.toPublicKey();
            const publicKeyBytes = typeof publicKey?.toBytes === 'function' ? publicKey.toBytes() : publicKey;
            return bytesToHex(publicKeyBytes);
        }
    }
    async getChainsafeBls() {
        if (!this.chainsafeBlsPromise) {
            this.chainsafeBlsPromise = import('@chainsafe/bls').then((m) => m?.default ?? m);
        }
        return this.chainsafeBlsPromise;
    }
    async getNobleBls() {
        if (!this.nobleBlsPromise) {
            this.nobleBlsPromise = import('@noble/curves/bls12-381').then((m) => m.bls12_381);
        }
        return this.nobleBlsPromise;
    }
}
