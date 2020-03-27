declare module 'sncrypto'
{
	export { SNPureCrypto } from './crypto/pure_crypto';
	export { SNWebCrypto } from './crypto/webcrypto';
	export { isWebCryptoAvailable, Buffer, stringToArrayBuffer, arrayBufferToString, arrayBufferToHexString, hexStringToArrayBuffer, base64ToArrayBuffer, arrayBufferToBase64, hexToBase64, base64ToHex, base64Encode, base64Decode, toBuffer, } from './utils';

	/**
	 * Abstract class with default implementations of basic helper functions.
	 */
	export class SNPureCrypto {
	    deinit(): void;
	    /**
	     * Generates a UUID string syncronously.
	     */
	    generateUUIDSync(): string;
	    /**
	     * Generates a UUID string asyncronously.
	     * Can be overriden by native platforms to provide async implementation
	     */
	    generateUUID(): Promise<string>;
	    /**
	     * Constant-time string comparison
	     * @param {string} a
	     * @param {string} b
	     */
	    timingSafeEqual(a: string, b: string): boolean;
	}

	import { SNPureCrypto } from '@Crypto/pure_crypto';
	/**
	 * The web crypto class allows access to a set of cryptographic primitives available
	 * in a web environment, consisting of two main sources:
	 * — Built-in browser WebCrypto
	 * — Libsodium.js library integration
	 */
	export class SNWebCrypto extends SNPureCrypto {
	    private ready;
	    constructor();
	    deinit(): void;
	    /**
	     * Derives a key from a password and salt using PBKDF2 via WebCrypto.
	     * @param {string} password - utf8 string
	     * @param {string} salt - utf8 string
	     * @param {number} iterations
	     * @param {number} length - In bits
	     * @returns Hex string
	     */
	    pbkdf2(password: string, salt: string, iterations: number, length: number): Promise<string | null>;
	    /**
	     * Generates a random key in hex format
	     * @param {number} bits - Length of key in bits
	     * @returns A string key in hex format
	     */
	    generateRandomKey(bits: number): Promise<string>;
	    /**
	     * Encrypts a string using AES-CBC via WebCrypto.
	     * @param {string} plaintext
	     * @param {string} iv - In hex format
	     * @param {string} key - In hex format
	     * @returns Ciphertext in Base64 format.
	     */
	    aes256CbcEncrypt(plaintext: string, iv: string, key: string): Promise<string>;
	    /**
	     * Decrypts a string using AES-CBC via WebCrypto.
	     * @param ciphertext - Base64 format
	     * @param iv - In hex format
	     * @param key - In hex format
	     * @returns Plain utf8 string or null if decryption fails
	     */
	    aes256CbcDecrypt(ciphertext: string, iv: string, key: string): Promise<string | null>;
	    /**
	     * Runs HMAC with SHA-256 on a message with key.
	     * @param message - Plain utf8 string
	     * @param key - In hex format
	     * @returns Hex string or null if computation fails
	     */
	    hmac256(message: string, key: string): Promise<string | null>;
	    /**
	     * @param {string} text - Plain utf8 string
	     * @returns Hex string
	     */
	    sha256(text: string): Promise<string>;
	    /**
	     * Use only for legacy applications.
	     * @param {string} text - Plain utf8 string
	     * @returns Hex string
	     */
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
	    /**
	     * Derives a key from a password and salt using
	     * argon2id (crypto_pwhash_ALG_DEFAULT).
	     * @param password - Plain text string
	     * @param salt - Salt in hex format
	     * @param iterations - The algorithm's opslimit (recommended min 2)
	     * @param bytes - The algorithm's memory limit (memlimit) (recommended min 67108864)
	     * @param length - The output key length
	     * @returns  Derived key in hex format
	     */
	    argon2(password: string, salt: string, iterations: number, bytes: number, length: number): Promise<string>;
	    /**
	     * Encrypt a message (and associated data) with XChaCha20-Poly1305.
	     * @param plaintext
	     * @param nonce - In hex format
	     * @param key - In hex format
	     * @param assocData
	     * @returns Base64 ciphertext string
	     */
	    xchacha20Encrypt(plaintext: string, nonce: string, key: string, assocData: string): Promise<string>;
	    /**
	     * Decrypt a message (and associated data) with XChaCha20-Poly1305
	     * @param ciphertext
	     * @param nonce - In hex format
	     * @param key - In hex format
	     * @param assocData
	     * @returns Plain utf8 string or null if decryption fails
	     */
	    xchacha20Decrypt(ciphertext: string, nonce: string, key: string, assocData: string): Promise<string | null>;
	}

	export { getGlobalScope, ieOrEdge, isWebCryptoAvailable, getSubtleCrypto, generateUUIDSync, } from './web_utils';
	export { isString, Buffer, toBuffer, stringToArrayBuffer, arrayBufferToString, arrayBufferToHexString, hexStringToArrayBuffer, base64ToArrayBuffer, arrayBufferToBase64, hexToBase64, base64ToHex, base64Encode, base64Decode, Format } from './common_utils';

	import { Buffer } from 'buffer';
	export { Buffer };
	export enum Format {
	    Utf8 = "utf8",
	    Base64 = "base64",
	    Hex = "hex",
	    Binary = "binary"
	}
	/**
	 * Determines if the input value is a string
	 */
	export function isString(value: any): boolean;
	/**
	 * Converts a plain string into an ArrayBuffer
	 * @param {string} string - A plain string
	 */
	export function stringToArrayBuffer(string: string): Promise<Uint8Array>;
	/**
	 * Converts an ArrayBuffer into a plain string
	 * @param {ArrayBuffer} arrayBuffer
	 */
	export function arrayBufferToString(arrayBuffer: ArrayBuffer): Promise<string>;
	/**
	 * Converts an ArrayBuffer into a hex string
	 * @param arrayBuffer
	 */
	export function arrayBufferToHexString(arrayBuffer: ArrayBuffer): Promise<string>;
	/**
	 * Converts a hex string into an ArrayBuffer
	 * @access public
	 * @param hex - A hex string
	 */
	export function hexStringToArrayBuffer(hex: string): Promise<Uint8Array>;
	/**
	 * Converts a base64 string into an ArrayBuffer
	 * @param base64 - A base64 string
	 */
	export function base64ToArrayBuffer(base64: string): Promise<Uint8Array>;
	/**
	 * Converts an ArrayBuffer into a base64 string
	 * @param buffer
	 */
	export function arrayBufferToBase64(arrayBuffer: ArrayBuffer): Promise<string>;
	/**
	 * Converts a hex string into a base64 string
	 * @param hex - A hex string
	 */
	export function hexToBase64(hex: string): Promise<string>;
	/**
	 * Converts a base64 string into a hex string
	 * @param base64 - A base64 string
	 */
	export function base64ToHex(base64: string): Promise<string>;
	/**
	 * Converts a plain string into base64
	 * @param text - A plain string
	 * @returns  A base64 encoded string
	 */
	export function base64Encode(text: string): Promise<string>;
	/**
	 * Converts a base64 string into a plain string
	 * @param base64String - A base64 encoded string
	 * @returns A plain string
	 */
	export function base64Decode(base64String: string): Promise<string>;
	/**
	 * Coerce input to a Buffer, throwing a TypeError if it cannot be coerced.
	 * @param stringOrBuffer
	 * @returns
	 */
	export function toBuffer(stringOrBuffer: string | ArrayBuffer, format?: Format): Promise<any>;

	export { ready, crypto_pwhash, crypto_pwhash_ALG_DEFAULT, crypto_aead_xchacha20poly1305_ietf_encrypt, crypto_aead_xchacha20poly1305_ietf_decrypt, to_base64, from_base64, base64_variants, from_hex, to_hex, from_string, to_string, } from 'libsodium-wrappers';

	global {
	    interface Document {
	        documentMode?: any;
	    }
	    interface Window {
	        msCrypto?: any;
	    }
	}
	/**
	 * Returns `window` if available, or `global` if supported in environment.
	 */
	export function getGlobalScope(): Window & typeof globalThis;
	/**
	 * Determines whether we are in an Internet Explorer or Edge environment
	 * @access public
	 */
	export function ieOrEdge(): any;
	/**
	 * Returns true if WebCrypto is available
	 * @access public
	 */
	export function isWebCryptoAvailable(): boolean;
	/**
	 * Returns the WebCrypto instance
	 * @access public
	 */
	export function getSubtleCrypto(): SubtleCrypto | null;
	/**
	 * Generates a UUID syncronously
	 * @access public
	 */
	export function generateUUIDSync(): string;

}