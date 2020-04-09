import { SNPureCrypto } from './pure_crypto';
/**
 * The web crypto class allows access to a set of cryptographic primitives available
 * in a web environment, consisting of two main sources:
 * — Built-in browser WebCrypto
 * — Libsodium.js library integration
 */
export declare class SNWebCrypto extends SNPureCrypto {
    private ready;
    constructor();
    deinit(): void;
    pbkdf2(password: string, salt: string, iterations: number, length: number): Promise<string | null>;
    generateRandomKey(bits: number): Promise<string>;
    aes256CbcEncrypt(plaintext: string, iv: string, key: string): Promise<string>;
    aes256CbcDecrypt(ciphertext: string, iv: string, key: string): Promise<string | null>;
    hmac256(message: string, key: string): Promise<string | null>;
    sha256(text: string): Promise<string>;
    unsafeSha1(text: string): Promise<string>;
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
    private webCryptoImportKey;
    /**
     * Performs WebCrypto PBKDF2 derivation.
     * @param {CryptoKey} key - A WebCrypto CryptoKey object
     * @param {string} salt - In utf8 format
     * @param {number} iterations
     * @param {number} length - In bits
     * @returns Hex string
     */
    private webCryptoDeriveBits;
    argon2(password: string, salt: string, iterations: number, bytes: number, length: number): Promise<string>;
    xchacha20Encrypt(plaintext: string, nonce: string, key: string, assocData: string): Promise<string>;
    xchacha20Decrypt(ciphertext: string, nonce: string, key: string, assocData: string): Promise<string | null>;
}
