import { SNPureCrypto } from '@Crypto/pure_crypto';
import * as Utils from "@Lib/web_utils";
const subtleCrypto = Utils.getSubtleCrypto();

export class SNWebCrypto extends SNPureCrypto {

  constructor() {
    super();
    this.ready = import('../libsodium').then((result) => {
      this.sodium = result;
      return this.sodium.ready;
    });
  }

  /** @public */
  async pbkdf2({ password, salt, iterations, length }) {
    const key = await this.webCryptoImportKey(password, "PBKDF2", ["deriveBits"]);
    if (!key) {
      console.log("Key is null, unable to continue");
      return null;
    }

    return this.webCryptoDeriveBits(key, salt, iterations, length);
  }

  /** @public */
  async generateRandomKey(bits) {
    const bytes = bits / 8;
    const arrayBuffer = Utils.getGlobalScope().crypto.getRandomValues(new Uint8Array(bytes));
    return Utils.arrayBufferToHexString(arrayBuffer);
  }

  /** @public */
  async aes256CbcEncrypt(text, keyData, ivData) {
    const alg = { name: 'AES-CBC', iv: ivData };
    const importedKeyData = await this.webCryptoImportKey(keyData, alg.name, ["encrypt"]);
    const textData = await Utils.stringToArrayBuffer(text);
    const result = await crypto.subtle.encrypt(alg, importedKeyData, textData);
    const ciphertext = await Utils.arrayBufferToBase64(result);
    return ciphertext;
  }

  /** @public */
  async aes256CbcDecrypt(ciphertext, keyData, ivData) {
    const alg = { name: 'AES-CBC', iv: ivData };
    const importedKeyData = await this.webCryptoImportKey(keyData, alg.name, ["decrypt"]);
    const textData = await Utils.base64ToArrayBuffer(ciphertext);
    return crypto.subtle.decrypt(alg, importedKeyData, textData).then(async (result) => {
      const decoded = await Utils.arrayBufferToString(result);
      return decoded;
    }).catch((error) => {
      console.error("Error decrypting:", error);
    });
  }

  /** @public */
  async aes256GcmEncrypt(text, keyData, ivData, aadData) {
    const alg = {
      name: 'AES-GCM',
      iv: ivData
    };
    if (aadData) { alg.additionalData = aadData; }
    const importedKeyData = await this.webCryptoImportKey(keyData, alg.name, ["encrypt"]);
    const textData = await Utils.stringToArrayBuffer(text);
    const result = await crypto.subtle.encrypt(alg, importedKeyData, textData);
    const ciphertext = await Utils.arrayBufferToBase64(result);
    return ciphertext;
  }

  /** @public */
  async aes256GcmDecrypt(ciphertext, keyData, ivData, aadData) {
    const alg = {
      name: 'AES-GCM',
      iv: ivData
    };
    if (aadData) { alg.additionalData = aadData; }
    const importedKeyData = await this.webCryptoImportKey(keyData, alg.name, ["decrypt"]);
    const textData = await Utils.base64ToArrayBuffer(ciphertext);
    return crypto.subtle.decrypt(alg, importedKeyData, textData).then(async (result) => {
      const decoded = await Utils.arrayBufferToString(result);
      return decoded;
    }).catch((error) => {
      console.error("Error decrypting:", error);
    });
  }

  /** @public */
  async hmac256(message, key) {
    const keyHexData = await Utils.hexStringToArrayBuffer(key);
    const keyData = await this.webCryptoImportKey(keyHexData, "HMAC", ["sign"], { name: "SHA-256" });
    const messageData = await Utils.stringToArrayBuffer(message);
    return crypto.subtle.sign({ name: "HMAC" }, keyData, messageData)
      .then(async (signature) => {
        const hash = await Utils.arrayBufferToHexString(signature);
        return hash;
      })
      .catch(function (err) {
        console.error("Error computing hmac", err);
      });
  }

  /** @public */
  async sha256(text) {
    const textData = await Utils.stringToArrayBuffer(text);
    const digest = await crypto.subtle.digest("SHA-256", textData);
    return Utils.arrayBufferToHexString(digest);
  }

  /**
   * @public
   * Use only for legacy applications.
   */
  // eslint-disable-next-line camelcase
  async unsafe_sha1(text) {
    const textData = await Utils.stringToArrayBuffer(text);
    const digest = await crypto.subtle.digest("SHA-1", textData);
    return Utils.arrayBufferToHexString(digest);
  }

  /** @private */
  async webCryptoImportKey(input, alg, actions, hash) {
    const text = typeof input === "string" ? await Utils.stringToArrayBuffer(input) : input;
    return subtleCrypto.importKey("raw", text, { name: alg, hash: hash }, false, actions)
      .then((key) => {
        return key;
      })
      .catch((err) => {
        console.error(err);
        return null;
      });
  }

  /** @private */
  async webCryptoDeriveBits(key, salt, iterations, length) {
    const params = {
      name: "PBKDF2",
      salt: await Utils.stringToArrayBuffer(salt),
      iterations: iterations,
      hash: { name: "SHA-512" },
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
   * @public
   * @param {string} password  Plain text string
   * @param {string} salt  Salt in hex format
   * @returns Hex string
   */
  async argon2({ password, salt, iterations, bytes, length }) {
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
   * Encrypt a message (and optional associated data) with XChaCha20-Poly1305.
   *
   * Throws a SodiumError if an invalid ciphertext/AAD is provided for this
   * nonce and key.
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
   * Decrypt a message (and optional associated data) with XChaCha20-Poly1305
   *
   * @param {String|Buffer} ciphertext
   * @param {String} nonce  In hex format
   * @param {String} key   In hex format
   * @param {String|Buffer} assocData
   */
  async xchacha20Decrypt(ciphertext, nonce, key, assocData) {
    await this.ready;
    if (nonce.length !== 48) {
      throw 'Nonce must be 24 bytes';
    }

    return this.sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      await Utils.toBuffer(ciphertext, 'base64'),
      await Utils.toBuffer(assocData),
      await Utils.toBuffer(nonce, 'hex'),
      await Utils.toBuffer(key, 'hex'),
      'text'
    );
  }
}
