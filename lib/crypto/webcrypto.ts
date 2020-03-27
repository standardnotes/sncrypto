import { SNPureCrypto } from '@Crypto/pure_crypto';
import * as Utils from '@Lib/utils';
import * as sodium from '@Lib/libsodium';

const subtleCrypto = Utils.getSubtleCrypto();

enum WebCryptoAlgs {
  AesCbc = 'AES-CBC',
  Sha512 = 'SHA-512',
  Sha256 = 'SHA-256',
  Pbkdf2 = 'PBKDF2',
  Sha1 = 'SHA-1',
  Hmac = 'HMAC'
};

enum WebCryptoActions {
  DeriveBits = 'deriveBits',
  Encrypt = 'encrypt',
  Decrypt = 'decrypt',
  Sign = 'sign'
};

type WebCryptoParams = {
  name: string,
  hash?: string
}
/**
 * The web crypto class allows access to a set of cryptographic primitives available
 * in a web environment, consisting of two main sources:
 * — Built-in browser WebCrypto
 * — Libsodium.js library integration
 */
export class SNWebCrypto extends SNPureCrypto {

  private ready: Promise<any> | null

  constructor() {
    super();
    /** Functions using Libsodium must await this 
     * promise before performing any library functions */
    this.ready = sodium.ready;
  }

  deinit() {
    super.deinit();
    this.ready = null;
  }

  /** 
   * Derives a key from a password and salt using PBKDF2 via WebCrypto.
   * @param {string} password - utf8 string
   * @param {string} salt - utf8 string
   * @param {number} iterations
   * @param {number} length - In bits
   * @returns Hex string
   */
  public async pbkdf2(
    password: string,
    salt: string,
    iterations: number,
    length: number
  ) {
    const keyData = await Utils.stringToArrayBuffer(password);
    const key = await this.webCryptoImportKey(
      keyData,
      WebCryptoAlgs.Pbkdf2,
      [WebCryptoActions.DeriveBits]
    );
    if (!key) {
      console.error('Key is null, unable to continue');
      return null;
    }
    return this.webCryptoDeriveBits(key, salt, iterations, length);
  }

  /** 
   * Generates a random key in hex format
   * @param {number} bits - Length of key in bits
   * @returns A string key in hex format
   */
  public async generateRandomKey(bits: number) {
    const bytes = bits / 8;
    const arrayBuffer = Utils.getGlobalScope().crypto.getRandomValues(new Uint8Array(bytes));
    return Utils.arrayBufferToHexString(arrayBuffer);
  }

  /** 
   * Encrypts a string using AES-CBC via WebCrypto.
   * @param {string} plaintext
   * @param {string} iv - In hex format
   * @param {string} key - In hex format
   * @returns Ciphertext in Base64 format.
   */
  public async aes256CbcEncrypt(plaintext: string, iv: string, key: string) {
    const keyData = await Utils.hexStringToArrayBuffer(key);
    const ivData = await Utils.hexStringToArrayBuffer(iv);
    const alg = { name: WebCryptoAlgs.AesCbc, iv: ivData };
    const importedKeyData = await this.webCryptoImportKey(
      keyData,
      alg.name,
      [WebCryptoActions.Encrypt]
    );
    const textData = await Utils.stringToArrayBuffer(plaintext);
    const result = await crypto.subtle.encrypt(
      alg,
      importedKeyData!,
      textData
    );
    const ciphertext = await Utils.arrayBufferToBase64(result);
    return ciphertext;
  }

  /**
   * Decrypts a string using AES-CBC via WebCrypto.
   * @param ciphertext - Base64 format
   * @param iv - In hex format
   * @param key - In hex format
   * @returns Plain utf8 string or null if decryption fails
   */
  public async aes256CbcDecrypt(
    ciphertext: string,
    iv: string,
    key: string
  ) {
    const keyData = await Utils.hexStringToArrayBuffer(key);
    const ivData = await Utils.hexStringToArrayBuffer(iv);
    const alg = { name: WebCryptoAlgs.AesCbc, iv: ivData };
    const importedKeyData = await this.webCryptoImportKey(
      keyData,
      alg.name,
      [WebCryptoActions.Decrypt]
    );
    const textData = await Utils.base64ToArrayBuffer(ciphertext);
    return crypto.subtle.decrypt(
      alg,
      importedKeyData!,
      textData
    ).then(async (result: ArrayBuffer) => {
      return Utils.arrayBufferToString(result);
    }, (_) => {
      return null;
    });
  }

  /** 
   * Runs HMAC with SHA-256 on a message with key.
   * @param message - Plain utf8 string
   * @param key - In hex format
   * @returns Hex string or null if computation fails
   */
  public async hmac256(message: string, key: string) {
    const keyHexData = await Utils.hexStringToArrayBuffer(key);
    const keyData = await this.webCryptoImportKey(
      keyHexData,
      WebCryptoAlgs.Hmac,
      [WebCryptoActions.Sign],
      { name: WebCryptoAlgs.Sha256 }
    );
    const messageData = await Utils.stringToArrayBuffer(message);
    const funcParams = { name: WebCryptoAlgs.Hmac } as any;
    return crypto.subtle.sign(
      funcParams,
      keyData!,
      messageData
    ).then((signature: ArrayBuffer) => {
      return Utils.arrayBufferToHexString(signature);
    }, (err: any) => {
      console.error('Error computing HMAC:', err);
      return null;
    });
  }

  /** 
   * @param {string} text - Plain utf8 string
   * @returns Hex string
   */
  public async sha256(text: string) {
    const textData = await Utils.stringToArrayBuffer(text);
    const digest = await crypto.subtle.digest(WebCryptoAlgs.Sha256, textData);
    return Utils.arrayBufferToHexString(digest);
  }

  /**
   * Use only for legacy applications.
   * @param {string} text - Plain utf8 string
   * @returns Hex string
   */
  public async unsafeSha1(text: string) {
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
  private async webCryptoImportKey(
    keyData: Uint8Array,
    alg: WebCryptoAlgs,
    actions: Array<WebCryptoActions>,
    hash?: WebCryptoParams
  ) {
    return subtleCrypto!.importKey(
      'raw',
      keyData,
      {
        name: alg,
        hash: hash!
      },
      false,
      actions
    ).then((key) => {
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
  private async webCryptoDeriveBits(
    key: CryptoKey,
    salt: string,
    iterations: number,
    length: number
  ) {
    const params = {
      name: WebCryptoAlgs.Pbkdf2,
      salt: await Utils.stringToArrayBuffer(salt),
      iterations: iterations,
      hash: { name: WebCryptoAlgs.Sha512 },
    };
    return subtleCrypto!.deriveBits(params, key, length).then((bits) => {
      return Utils.arrayBufferToHexString(new Uint8Array(bits));
    });
  }

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
  public async argon2(
    password: string,
    salt: string,
    iterations: number,
    bytes: number,
    length: number
  ) {
    await this.ready;
    const result = sodium.crypto_pwhash(
      length,
      await Utils.toBuffer(password, Utils.Format.Binary),
      await Utils.toBuffer(salt, Utils.Format.Hex),
      iterations,
      bytes,
      sodium.crypto_pwhash_ALG_DEFAULT,
      'hex'
    );
    return result;
  }

  /**
   * Encrypt a message (and associated data) with XChaCha20-Poly1305.
   * @param plaintext
   * @param nonce - In hex format
   * @param key - In hex format
   * @param assocData
   * @returns Base64 ciphertext string
   */
  public async xchacha20Encrypt(
    plaintext: string,
    nonce: string,
    key: string,
    assocData: string
  ) {
    await this.ready;
    if (nonce.length !== 48) {
      throw 'Nonce must be 24 bytes';
    }
    return sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      await Utils.toBuffer(plaintext),
      await Utils.toBuffer(assocData),
      null,
      await Utils.toBuffer(nonce, Utils.Format.Hex),
      await Utils.toBuffer(key, Utils.Format.Hex),
      'base64'
    );
  }

  /**
   * Decrypt a message (and associated data) with XChaCha20-Poly1305
   * @param ciphertext
   * @param nonce - In hex format
   * @param key - In hex format
   * @param assocData
   * @returns Plain utf8 string or null if decryption fails
   */
  public async xchacha20Decrypt(
    ciphertext: string,
    nonce: string,
    key: string,
    assocData: string
  ) {
    await this.ready;
    if (nonce.length !== 48) {
      throw 'Nonce must be 24 bytes';
    }
    try {
      return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        await Utils.toBuffer(ciphertext, Utils.Format.Base64),
        await Utils.toBuffer(assocData),
        await Utils.toBuffer(nonce, Utils.Format.Hex),
        await Utils.toBuffer(key, Utils.Format.Hex),
        'text'
      );
    } catch {
      return null;
    }
  }
}
