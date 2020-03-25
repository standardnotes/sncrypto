import { SNPureCrypto } from '@Crypto/pure_crypto';
import * as Utils from '@Lib/utils';
import * as sodium from '@Lib/libsodium';;

const subtleCrypto = Utils.getSubtleCrypto();
const WebCryptoAlgs = {
  AesCbc: 'AES-CBC',
  Sha512: 'SHA-512',
  Sha256: 'SHA-256',
  Pbkdf2: 'PBKDF2',
  Sha1: 'SHA-1',
  Hmac: 'HMAC'
};
const WebCryptoActions = {
  DeriveBits: 'deriveBits',
  Encrypt: 'encrypt',
  Decrypt: 'decrypt',
  Sign: 'sign'
};
/**
 * The web crypto class allows access to a set of cryptographic primitives available
 * in a web environment, consisting of two main sources:
 * — Built-in browser WebCrypto
 * — Libsodium.js library integration
 */
export class SNWebCrypto extends SNPureCrypto {
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
   * @access public 
   * @param {string} password
   * @param {string} salt - In hex format
   * @param {number} iterations
   * @param {number} length - In bits
   * @returns {Promise<string|null>} Hex string
   */
  async pbkdf2(password, salt, iterations, length) {
    const key = await this.webCryptoImportKey(
      password,
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
   * @access public
   * @param {number} bits - Length of key in bits
   * @returns {Promise<string>} A string key in hex format
   */
  async generateRandomKey(bits) {
    const bytes = bits / 8;
    const arrayBuffer = Utils.getGlobalScope().crypto.getRandomValues(new Uint8Array(bytes));
    return Utils.arrayBufferToHexString(arrayBuffer);
  }

  /** 
   * Encrypts a string using AES-CBC via WebCrypto.
   * @access public 
   * @param {string} plaintext
   * @param {string} iv - In hex format
   * @param {string} key - In hex format
   * @returns {Promise<string>} Ciphertext in Base64 format.
   */
  async aes256CbcEncrypt(plaintext, iv, key) {
    const keyData = await Utils.hexStringToArrayBuffer(key);
    const ivData = await Utils.hexStringToArrayBuffer(iv);
    const alg = { name: WebCryptoAlgs.AesCbc, iv: ivData };
    const importedKeyData = await this.webCryptoImportKey(
      keyData,
      alg.name,
      [WebCryptoActions.Encrypt]
    );
    const textData = await Utils.stringToArrayBuffer(plaintext);
    const result = await crypto.subtle.encrypt(alg, importedKeyData, textData);
    const ciphertext = await Utils.arrayBufferToBase64(result);
    return ciphertext;
  }

  /**
   * Decrypts a string using AES-CBC via WebCrypto.
   * @access public
   * @param {string} ciphertext - Base64 format
   * @param {string} iv - In hex format
   * @param {string} key - In hex format
   * @returns {Promise<string|null>} Plain utf8 string or null if decryption fails
   */
  async aes256CbcDecrypt(ciphertext, iv, key) {
    const keyData = await Utils.hexStringToArrayBuffer(key);
    const ivData = await Utils.hexStringToArrayBuffer(iv);
    const alg = { name: WebCryptoAlgs.AesCbc, iv: ivData };
    const importedKeyData = await this.webCryptoImportKey(
      keyData,
      alg.name,
      [WebCryptoActions.Decrypt]
    );
    const textData = await Utils.base64ToArrayBuffer(ciphertext);
    return crypto.subtle.decrypt(alg, importedKeyData, textData).then(async (result) => {
      return Utils.arrayBufferToString(result);
    }).catch((error) => {
      console.error('Error performing AES-CBC decryption:', error);
      return null;
    });
  }

  /** 
   * Runs HMAC with SHA-256 on a message with key.
   * @access public 
   * @param {string} message - Plain utf8 string
   * @param {string} key - In hex format
   * @returns {Promise<string|null>} Hex string or null if computation fails
   */
  async hmac256(message, key) {
    const keyHexData = await Utils.hexStringToArrayBuffer(key);
    const keyData = await this.webCryptoImportKey(
      keyHexData,
      WebCryptoAlgs.Hmac,
      [WebCryptoActions.Sign],
      { name: WebCryptoAlgs.Sha256 }
    );
    const messageData = await Utils.stringToArrayBuffer(message);
    return crypto.subtle.sign(
      { name: WebCryptoAlgs.Hmac },
      keyData,
      messageData
    ).then((signature) => {
      return Utils.arrayBufferToHexString(signature);
    }).catch((err) => {
      console.error('Error computing HMAC:', err);
      return null;
    });
  }

  /** 
   * @access public 
   * @param {string} text - Plain utf8 string
   * @returns {Promise<string>} Hex string
   */
  async sha256(text) {
    const textData = await Utils.stringToArrayBuffer(text);
    const digest = await crypto.subtle.digest(WebCryptoAlgs.Sha256, textData);
    return Utils.arrayBufferToHexString(digest);
  }

  /**
   * Use only for legacy applications.
   * @access public
   * @param {string} text - Plain utf8 string
   * @returns {Promise<string>} Hex string
   */
  async unsafeSha1(text) {
    const textData = await Utils.stringToArrayBuffer(text);
    const digest = await crypto.subtle.digest(WebCryptoAlgs.Sha1, textData);
    return Utils.arrayBufferToHexString(digest);
  }

  /** 
   * Converts a raw string key to a WebCrypto CryptoKey object.
   * @access private 
   * @param {string|Buffer} rawKey
   *    A plain utf8 string or an array buffer
   * @param {string|WebCryptoAlgs} alg 
   *    The name of the algorithm this key will be used for (i.e 'AES-CBC' or 'HMAC')
   * @param {Array.<string|WebCryptoActions>} actions 
   *    The actions this key will be used for (i.e 'deriveBits' or 'encrypt')
   * @param {object} [hash] 
   *    An optional object representing the hashing function this key is intended to be
   *    used for. This option is only supplied when the `alg` is HMAC.
   * @param {string|WebCryptoAlgs} hash.name
   *    The name of the hashing function to use with HMAC.
   * @returns {Promise<CryptoKey|null>} A WebCrypto CryptoKey object
   */
  async webCryptoImportKey(rawKey, alg, actions, hash) {
    const keyData = Utils.isString(rawKey) ? await Utils.stringToArrayBuffer(rawKey) : rawKey;
    return subtleCrypto.importKey(
      'raw',
      keyData,
      { name: alg, hash: hash },
      false,
      actions
    ).then((key) => {
      return key;
    }).catch((err) => {
      console.error(err);
      return null;
    });
  }

  /** 
   * Performs WebCrypto PBKDF2 derivation.
   * @access private
   * @param {CryptoKey} key - A WebCrypto CryptoKey object
   * @param {string} salt - In hex format
   * @param {number} iterations
   * @param {number} length - In bits
   * @returns {Promise<string|null>} Hex string
   */
  async webCryptoDeriveBits(key, salt, iterations, length) {
    const params = {
      name: WebCryptoAlgs.Pbkdf2,
      salt: await Utils.hexStringToArrayBuffer(salt),
      iterations: iterations,
      hash: { name: WebCryptoAlgs.Sha512 },
    };
    return subtleCrypto.deriveBits(params, key, length).then((bits) => {
      return Utils.arrayBufferToHexString(new Uint8Array(bits));
    }).catch((err) => {
      console.error(err);
      return null;
    });
  }

  /**
   * Derives a key from a password and salt using 
   * argon2id (crypto_pwhash_ALG_DEFAULT).
   * @param {string} password - Plain text string
   * @param {string} salt - Salt in hex format
   * @param {string} iterations - The algorithm's opslimit (recommended min 2)
   * @param {string} bytes - The algorithm's memory limit (memlimit) (recommended min 67108864)
   * @param {string} length - The output key length
   * @returns {Promise<string>} Derived key in hex format
   */
  async argon2(password, salt, iterations, bytes, length) {
    await this.ready;
    const result = sodium.crypto_pwhash(
      length,
      await Utils.toBuffer(password, 'binary'),
      await Utils.toBuffer(salt, 'hex'),
      iterations,
      bytes,
      sodium.crypto_pwhash_ALG_DEFAULT,
      'hex'
    );
    return result;
  }

  /**
   * Encrypt a message (and associated data) with XChaCha20-Poly1305.
   * @param {string|Buffer} plaintext
   * @param {string|Buffer} nonce - In hex format
   * @param {string|Buffer} key - In hex format
   * @param {string|Buffer} assocData
   * @returns {Promise<string>} Base64 ciphertext string
   */
  async xchacha20Encrypt(plaintext, nonce, key, assocData) {
    await this.ready;
    if (nonce.length !== 48) {
      throw 'Nonce must be 24 bytes';
    }
    return sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      await Utils.toBuffer(plaintext),
      await Utils.toBuffer(assocData),
      null,
      await Utils.toBuffer(nonce, 'hex'),
      await Utils.toBuffer(key, 'hex'),
      'base64'
    );
  }

  /**
   * Decrypt a message (and associated data) with XChaCha20-Poly1305
   * @param {string|Buffer} ciphertext
   * @param {string|Buffer} nonce - In hex format
   * @param {string|Buffer} key - In hex format
   * @param {string|Buffer} assocData
   * @returns {Promise<string|null>} Plain utf8 string or null if decryption fails
   */
  async xchacha20Decrypt(ciphertext, nonce, key, assocData) {
    await this.ready;
    if (nonce.length !== 48) {
      throw 'Nonce must be 24 bytes';
    }
    try {
      return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        await Utils.toBuffer(ciphertext, 'base64'),
        await Utils.toBuffer(assocData),
        await Utils.toBuffer(nonce, 'hex'),
        await Utils.toBuffer(key, 'hex'),
        'text'
      );
    } catch {
      return null;
    }
  }
}
