import * as Utils from './utils';
import * as sodium from './libsodium';
const subtleCrypto = Utils.getSubtleCrypto();
var WebCryptoAlgs;
(function (WebCryptoAlgs) {
    WebCryptoAlgs["AesCbc"] = "AES-CBC";
    WebCryptoAlgs["Sha512"] = "SHA-512";
    WebCryptoAlgs["Sha256"] = "SHA-256";
    WebCryptoAlgs["Pbkdf2"] = "PBKDF2";
    WebCryptoAlgs["Sha1"] = "SHA-1";
    WebCryptoAlgs["Hmac"] = "HMAC";
})(WebCryptoAlgs || (WebCryptoAlgs = {}));
;
var WebCryptoActions;
(function (WebCryptoActions) {
    WebCryptoActions["DeriveBits"] = "deriveBits";
    WebCryptoActions["Encrypt"] = "encrypt";
    WebCryptoActions["Decrypt"] = "decrypt";
    WebCryptoActions["Sign"] = "sign";
})(WebCryptoActions || (WebCryptoActions = {}));
;
/**
 * The web crypto class allows access to a set of cryptographic primitives available
 * in a web environment, consisting of two main sources:
 * — Built-in browser WebCrypto
 * — Libsodium.js library integration
 */
export class SNWebCrypto {
    constructor() {
        /** Functions using Libsodium must await this
         * promise before performing any library functions */
        this.ready = sodium.ready;
    }
    deinit() {
        this.ready = null;
    }
    generateUUIDSync() {
        return Utils.generateUUIDSync();
    }
    async generateUUID() {
        return Utils.generateUUIDSync();
    }
    timingSafeEqual(a, b) {
        return Utils.timingSafeEqual(a, b);
    }
    async base64Encode(text) {
        return Utils.base64Encode(text);
    }
    async base64Decode(base64String) {
        return Utils.base64Decode(base64String);
    }
    async pbkdf2(password, salt, iterations, length) {
        const keyData = await Utils.stringToArrayBuffer(password);
        const key = await this.webCryptoImportKey(keyData, WebCryptoAlgs.Pbkdf2, [WebCryptoActions.DeriveBits]);
        if (!key) {
            console.error('Key is null, unable to continue');
            return null;
        }
        return this.webCryptoDeriveBits(key, salt, iterations, length);
    }
    async generateRandomKey(bits) {
        const bytes = bits / 8;
        const arrayBuffer = Utils.getGlobalScope().crypto.getRandomValues(new Uint8Array(bytes));
        return Utils.arrayBufferToHexString(arrayBuffer);
    }
    async aes256CbcEncrypt(plaintext, iv, key) {
        const keyData = await Utils.hexStringToArrayBuffer(key);
        const ivData = await Utils.hexStringToArrayBuffer(iv);
        const alg = { name: WebCryptoAlgs.AesCbc, iv: ivData };
        const importedKeyData = await this.webCryptoImportKey(keyData, alg.name, [WebCryptoActions.Encrypt]);
        const textData = await Utils.stringToArrayBuffer(plaintext);
        const result = await crypto.subtle.encrypt(alg, importedKeyData, textData);
        const ciphertext = await Utils.arrayBufferToBase64(result);
        return ciphertext;
    }
    async aes256CbcDecrypt(ciphertext, iv, key) {
        const keyData = await Utils.hexStringToArrayBuffer(key);
        const ivData = await Utils.hexStringToArrayBuffer(iv);
        const alg = { name: WebCryptoAlgs.AesCbc, iv: ivData };
        const importedKeyData = await this.webCryptoImportKey(keyData, alg.name, [WebCryptoActions.Decrypt]);
        const textData = await Utils.base64ToArrayBuffer(ciphertext);
        return crypto.subtle.decrypt(alg, importedKeyData, textData).then(async (result) => {
            return Utils.arrayBufferToString(result);
        }, (_) => {
            return null;
        });
    }
    async hmac256(message, key) {
        const keyHexData = await Utils.hexStringToArrayBuffer(key);
        const keyData = await this.webCryptoImportKey(keyHexData, WebCryptoAlgs.Hmac, [WebCryptoActions.Sign], { name: WebCryptoAlgs.Sha256 });
        const messageData = await Utils.stringToArrayBuffer(message);
        const funcParams = { name: WebCryptoAlgs.Hmac };
        return crypto.subtle.sign(funcParams, keyData, messageData).then((signature) => {
            return Utils.arrayBufferToHexString(signature);
        }, (err) => {
            console.error('Error computing HMAC:', err);
            return null;
        });
    }
    async sha256(text) {
        const textData = await Utils.stringToArrayBuffer(text);
        const digest = await crypto.subtle.digest(WebCryptoAlgs.Sha256, textData);
        return Utils.arrayBufferToHexString(digest);
    }
    async unsafeSha1(text) {
        const textData = await Utils.stringToArrayBuffer(text);
        const digest = await crypto.subtle.digest(WebCryptoAlgs.Sha1, textData);
        return Utils.arrayBufferToHexString(digest);
    }
    /**
     * Converts a raw string key to a WebCrypto CryptoKey object.
     * @param rawKey
     *    A plain utf8 string or an array buffer
     * @param alg
     *    The name of the algorithm this key will be used for (i.e 'AES-CBC' or 'HMAC')
     * @param actions
     *    The actions this key will be used for (i.e 'deriveBits' or 'encrypt')
     * @param hash
     *    An optional object representing the hashing function this key is intended to be
     *    used for. This option is only supplied when the `alg` is HMAC.
     * @param hash.name
     *    The name of the hashing function to use with HMAC.
     * @returns A WebCrypto CryptoKey object
     */
    async webCryptoImportKey(keyData, alg, actions, hash) {
        return subtleCrypto.importKey('raw', keyData, {
            name: alg,
            hash: hash
        }, false, actions).then((key) => {
            return key;
        }, (_) => {
            return null;
        });
    }
    /**
     * Performs WebCrypto PBKDF2 derivation.
     * @param {CryptoKey} key - A WebCrypto CryptoKey object
     * @param {string} salt - In utf8 format
     * @param {number} iterations
     * @param {number} length - In bits
     * @returns Hex string
     */
    async webCryptoDeriveBits(key, salt, iterations, length) {
        const params = {
            name: WebCryptoAlgs.Pbkdf2,
            salt: await Utils.stringToArrayBuffer(salt),
            iterations: iterations,
            hash: { name: WebCryptoAlgs.Sha512 },
        };
        return subtleCrypto.deriveBits(params, key, length).then((bits) => {
            return Utils.arrayBufferToHexString(new Uint8Array(bits));
        });
    }
    async argon2(password, salt, iterations, bytes, length) {
        await this.ready;
        const result = sodium.crypto_pwhash(length, await Utils.toBuffer(password, Utils.Format.Binary), await Utils.toBuffer(salt, Utils.Format.Hex), iterations, bytes, sodium.crypto_pwhash_ALG_DEFAULT, 'hex');
        return result;
    }
    async xchacha20Encrypt(plaintext, nonce, key, assocData) {
        await this.ready;
        if (nonce.length !== 48) {
            throw 'Nonce must be 24 bytes';
        }
        return sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(await Utils.toBuffer(plaintext), await Utils.toBuffer(assocData), null, await Utils.toBuffer(nonce, Utils.Format.Hex), await Utils.toBuffer(key, Utils.Format.Hex), 'base64');
    }
    async xchacha20Decrypt(ciphertext, nonce, key, assocData) {
        await this.ready;
        if (nonce.length !== 48) {
            throw 'Nonce must be 24 bytes';
        }
        try {
            return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, await Utils.toBuffer(ciphertext, Utils.Format.Base64), await Utils.toBuffer(assocData), await Utils.toBuffer(nonce, Utils.Format.Hex), await Utils.toBuffer(key, Utils.Format.Hex), 'text');
        }
        catch {
            return null;
        }
    }
}
