import { SNPureCrypto, HexString, Utf8String, Base64String } from '../common/pure_crypto';
/**
 * The web crypto class allows access to a set of cryptographic primitives available
 * in a web environment, consisting of two main sources:
 * — Built-in browser WebCrypto
 * — Libsodium.js library integration
 */
export declare class SNWebCrypto implements SNPureCrypto {
    private ready;
    constructor();
    deinit(): void;
    generateUUIDSync(): string;
    generateUUID(): Promise<string>;
    timingSafeEqual(a: string, b: string): boolean;
    base64Encode(text: Utf8String): Promise<string>;
    base64Decode(base64String: Base64String): Promise<string>;
    pbkdf2(password: Utf8String, salt: Utf8String, iterations: number, length: number): Promise<string | null>;
    generateRandomKey(bits: number): Promise<string>;
    aes256CbcEncrypt(plaintext: Utf8String, iv: HexString, key: HexString): Promise<Base64String>;
    aes256CbcDecrypt(ciphertext: Base64String, iv: HexString, key: HexString): Promise<Utf8String | null>;
    hmac256(message: Utf8String, key: HexString): Promise<HexString | null>;
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
     * @param key - A WebCrypto CryptoKey object
     * @param length - In bits
     */
    private webCryptoDeriveBits;
    argon2(password: Utf8String, salt: HexString, iterations: number, bytes: number, length: number): Promise<HexString>;
    xchacha20Encrypt(plaintext: Utf8String, nonce: HexString, key: HexString, assocData: Utf8String): Promise<Base64String>;
    xchacha20Decrypt(ciphertext: Base64String, nonce: HexString, key: HexString, assocData: Utf8String | Uint8Array): Promise<Utf8String | null>;
}
