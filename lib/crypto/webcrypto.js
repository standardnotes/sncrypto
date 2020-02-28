import { SNPureCrypto } from '@Crypto/pure_crypto';
import * as Utils from '@Lib/web_utils';
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
 * - Built-in browser WebCrypto
 * - Libsodium.js library integration
 */
export class SNWebCrypto extends SNPureCrypto {
  constructor() {
    super();
    this.ready = import(/* webpackChunkName: 'libsodium' */ '../libsodium')
      .then((result) => {
        this.sodium = result;
        return this.sodium.ready;
      });
  }

  /** 
   * @access public 
   * @param {String} password
   * @param {String} salt  In hex format
   * @param {Int} iterations
   * @param {Int} length  In bits
   */
  async pbkdf2(password, salt, iterations, length) {
    const key = await this.webCryptoImportKey(
      password,
      WebCryptoAlgs.Pbkdf2,
      [WebCryptoActions.DeriveBits]
    );
    if (!key) {
      console.log('Key is null, unable to continue');
      return null;
    }
    return this.webCryptoDeriveBits(key, salt, iterations, length);
  }

  /** @access public */
  async generateRandomKey(bits) {
    const bytes = bits / 8;
    const arrayBuffer = Utils.getGlobalScope().crypto.getRandomValues(new Uint8Array(bytes));
    return Utils.arrayBufferToHexString(arrayBuffer);
  }

  /** @access public */
  async aes256CbcEncrypt(text, key, iv) {
    const keyData = await Utils.hexStringToArrayBuffer(key);
    const ivData = await Utils.hexStringToArrayBuffer(iv);
    const alg = { name: WebCryptoAlgs.AesCbc, iv: ivData };
    const importedKeyData = await this.webCryptoImportKey(
      keyData,
      alg.name,
      [WebCryptoActions.Encrypt]
    );
    const textData = await Utils.stringToArrayBuffer(text);
    const result = await crypto.subtle.encrypt(alg, importedKeyData, textData);
    const ciphertext = await Utils.arrayBufferToBase64(result);
    return ciphertext;
  }

  /** @access public */
  async aes256CbcDecrypt(ciphertext, key, iv) {
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
      const decoded = await Utils.arrayBufferToString(result);
      return decoded;
    }).catch((error) => {
      console.error('Error decrypting:', error);
    });
  }

  /** @access public */
  async hmac256(message, key) {
    const keyHexData = await Utils.hexStringToArrayBuffer(key);
    const keyData = await this.webCryptoImportKey(
      keyHexData,
      WebCryptoAlgs.Hmac,
      [WebCryptoActions.Sign],
      { name: WebCryptoAlgs.Sha256 }
    );
    const messageData = await Utils.stringToArrayBuffer(message);
    return crypto.subtle.sign({ name: WebCryptoAlgs.Hmac }, keyData, messageData)
      .then(async (signature) => {
        const hash = await Utils.arrayBufferToHexString(signature);
        return hash;
      })
      .catch(function (err) {
        console.error('Error computing hmac', err);
      });
  }

  /** @access public */
  async sha256(text) {
    const textData = await Utils.stringToArrayBuffer(text);
    const digest = await crypto.subtle.digest(WebCryptoAlgs.Sha256, textData);
    return Utils.arrayBufferToHexString(digest);
  }

  /**
   * @access public
   * Use only for legacy applications.
   */
  // eslint-disable-next-line camelcase
  async unsafe_sha1(text) {
    const textData = await Utils.stringToArrayBuffer(text);
    const digest = await crypto.subtle.digest(WebCryptoAlgs.Sha1, textData);
    return Utils.arrayBufferToHexString(digest);
  }

  /** @access private */
  async webCryptoImportKey(input, alg, actions, hash) {
    const text = typeof input === 'string' ? await Utils.stringToArrayBuffer(input) : input;
    return subtleCrypto.importKey('raw', text, { name: alg, hash: hash }, false, actions)
      .then((key) => {
        return key;
      })
      .catch((err) => {
        console.error(err);
        return null;
      });
  }

  /** @access private */
  async webCryptoDeriveBits(key, salt, iterations, length) {
    const params = {
      name: WebCryptoAlgs.Pbkdf2,
      salt: await Utils.stringToArrayBuffer(salt),
      iterations: iterations,
      hash: { name: WebCryptoAlgs.Sha512 },
    };
    return subtleCrypto.deriveBits(params, key, length)
      .then(async (bits) => {
        const key = await Utils.arrayBufferToHexString(new Uint8Array(bits));
        return key;
      })
      .catch((err) => {
        console.error(err);
        return null;
      });
  }

  /**
   * @param {string} password  Plain text string
   * @param {string} salt  Salt in hex format
   * @returns Hex string
   */
  async argon2(password, salt, iterations, bytes, length) {
    await this.ready;
    const result = this.sodium.crypto_pwhash(
      length,
      await Utils.toBuffer(password, 'binary'),
      await Utils.toBuffer(salt, 'hex'),
      iterations,
      bytes,
      this.sodium.crypto_pwhash_ALG_DEFAULT,
      'hex'
    );
    return result;
  }

  /**
   * Encrypt a message (and associated data) with XChaCha20-Poly1305.
   * 
   * @param {String|Buffer} plaintext
   * @param {String} nonce  In hex format
   * @param {String} key   In hex format
   * @param {String|Buffer} assocData
   */
  async xchacha20Encrypt(plaintext, nonce, key, assocData) {
    await this.ready;
    if (nonce.length !== 48) {
      throw 'Nonce must be 24 bytes';
    }
    return this.sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
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
   *
   * @param {String|Buffer} ciphertext
   * @param {String} nonce  In hex format
   * @param {String} key  In hex format
   * @param {String|Buffer} assocData
   */
  async xchacha20Decrypt(ciphertext, nonce, key, assocData) {
    await this.ready;
    if (nonce.length !== 48) {
      throw 'Nonce must be 24 bytes';
    }
    try {
      return this.sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        await Utils.toBuffer(ciphertext, 'base64'),
        await Utils.toBuffer(assocData),
        await Utils.toBuffer(nonce, 'hex'),
        await Utils.toBuffer(key, 'hex'),
        'text'
      );
    } catch (error) {
      return null;
    }
  }
}
