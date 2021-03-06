import * as Utils from './utils'
import * as sodium from './libsodium'

import {
  Base64String,
  HexString,
  SNPureCrypto,
  Utf8String,
  timingSafeEqual
} from '@standardnotes/sncrypto-common'

const subtleCrypto = Utils.getSubtleCrypto()

enum WebCryptoAlgs {
  AesCbc = 'AES-CBC',
  Sha512 = 'SHA-512',
  Sha256 = 'SHA-256',
  Pbkdf2 = 'PBKDF2',
  Sha1 = 'SHA-1',
  Hmac = 'HMAC'
}

enum WebCryptoActions {
  DeriveBits = 'deriveBits',
  Encrypt = 'encrypt',
  Decrypt = 'decrypt',
  Sign = 'sign'
}

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
export class SNWebCrypto implements SNPureCrypto {

  private ready: Promise<void> | null

  constructor() {
    /** Functions using Libsodium must await this
     * promise before performing any library functions */
    this.ready = sodium.ready
  }

  deinit(): void {
    this.ready = null
  }

  public generateUUIDSync(): string {
    return Utils.generateUUIDSync()
  }

  public async generateUUID(): Promise<string> {
    return Utils.generateUUIDSync()
  }

  public timingSafeEqual(a: string, b: string): boolean {
    return timingSafeEqual(a, b)
  }

  public async base64Encode(text: Utf8String): Promise<string> {
    return Utils.base64Encode(text)
  }

  public async base64Decode(base64String: Base64String): Promise<string> {
    return Utils.base64Decode(base64String)
  }

  public async pbkdf2(
    password: Utf8String,
    salt: Utf8String,
    iterations: number,
    length: number
  ): Promise<HexString | null> {
    const keyData = await Utils.stringToArrayBuffer(password)
    const key = await this.webCryptoImportKey(
      keyData,
      WebCryptoAlgs.Pbkdf2,
      [WebCryptoActions.DeriveBits]
    )
    if (!key) {
      console.error('Key is null, unable to continue')
      return null
    }
    return this.webCryptoDeriveBits(key, salt, iterations, length)
  }

  public async generateRandomKey(bits: number): Promise<string> {
    const bytes = bits / 8
    const arrayBuffer = Utils.getGlobalScope().crypto.getRandomValues(new Uint8Array(bytes))
    return Utils.arrayBufferToHexString(arrayBuffer)
  }

  public async aes256CbcEncrypt(
    plaintext: Utf8String,
    iv: HexString,
    key: HexString
  ): Promise<Base64String> {
    const keyData = await Utils.hexStringToArrayBuffer(key)
    const ivData = await Utils.hexStringToArrayBuffer(iv)
    const alg = { name: WebCryptoAlgs.AesCbc, iv: ivData }
    const importedKeyData = await this.webCryptoImportKey(
      keyData,
      alg.name,
      [WebCryptoActions.Encrypt]
    )
    const textData = await Utils.stringToArrayBuffer(plaintext)
    const result = await crypto.subtle.encrypt(
      alg,
      importedKeyData,
      textData
    )
    return Utils.arrayBufferToBase64(result)
  }

  public async aes256CbcDecrypt(
    ciphertext: Base64String,
    iv: HexString,
    key: HexString
  ): Promise<Utf8String | null> {
    const keyData = await Utils.hexStringToArrayBuffer(key)
    const ivData = await Utils.hexStringToArrayBuffer(iv)
    const alg = { name: WebCryptoAlgs.AesCbc, iv: ivData }
    const importedKeyData = await this.webCryptoImportKey(
      keyData,
      alg.name,
      [WebCryptoActions.Decrypt]
    )
    const textData = await Utils.base64ToArrayBuffer(ciphertext)

    try {
      const result = await crypto.subtle.decrypt(
        alg,
        importedKeyData,
        textData
      )

      return Utils.arrayBufferToString(result)
    } catch {
      return null
    }
  }

  public async hmac256(
    message: Utf8String,
    key: HexString
  ): Promise<HexString | null> {
    const keyHexData = await Utils.hexStringToArrayBuffer(key)
    const keyData = await this.webCryptoImportKey(
      keyHexData,
      WebCryptoAlgs.Hmac,
      [WebCryptoActions.Sign],
      { name: WebCryptoAlgs.Sha256 }
    )
    const messageData = await Utils.stringToArrayBuffer(message)
    const funcParams = { name: WebCryptoAlgs.Hmac }

    try {
      const signature = await crypto.subtle.sign(
        funcParams,
        keyData,
        messageData
      )

      return Utils.arrayBufferToHexString(signature)
    } catch (error) {
      console.error('Error computing HMAC:', error)

      return null
    }
  }

  public async sha256(text: string): Promise<string> {
    const textData = await Utils.stringToArrayBuffer(text)
    const digest = await crypto.subtle.digest(WebCryptoAlgs.Sha256, textData)
    return Utils.arrayBufferToHexString(digest)
  }

  public async unsafeSha1(text: string): Promise<string> {
    const textData = await Utils.stringToArrayBuffer(text)
    const digest = await crypto.subtle.digest(WebCryptoAlgs.Sha1, textData)
    return Utils.arrayBufferToHexString(digest)
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
  ): Promise<CryptoKey> {
    return subtleCrypto.importKey(
      'raw',
      keyData,
      {
        name: alg,
        hash: hash
      },
      false,
      actions
    )
  }

  /**
   * Performs WebCrypto PBKDF2 derivation.
   * @param key - A WebCrypto CryptoKey object
   * @param length - In bits
   */
  private async webCryptoDeriveBits(
    key: CryptoKey,
    salt: Utf8String,
    iterations: number,
    length: number
  ): Promise<HexString> {
    const params = {
      name: WebCryptoAlgs.Pbkdf2,
      salt: await Utils.stringToArrayBuffer(salt),
      iterations: iterations,
      hash: { name: WebCryptoAlgs.Sha512 },
    }

    return subtleCrypto.deriveBits(params, key, length).then((bits) => {
      return Utils.arrayBufferToHexString(new Uint8Array(bits))
    })
  }

  public async argon2(
    password: Utf8String,
    salt: HexString,
    iterations: number,
    bytes: number,
    length: number
  ): Promise<HexString> {
    await this.ready
    const result = sodium.crypto_pwhash(
      length,
      await Utils.stringToArrayBuffer(password),
      await Utils.hexStringToArrayBuffer(salt),
      iterations,
      bytes,
      sodium.crypto_pwhash_ALG_DEFAULT,
      'hex'
    )
    return result
  }

  public async xchacha20Encrypt(
    plaintext: Utf8String,
    nonce: HexString,
    key: HexString,
    assocData: Utf8String
  ): Promise<Base64String> {
    await this.ready
    if (nonce.length !== 48) {
      throw Error('Nonce must be 24 bytes')
    }
    const arrayBuffer = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      plaintext,
      assocData,
      null,
      await Utils.hexStringToArrayBuffer(nonce),
      await Utils.hexStringToArrayBuffer(key)
    )
    return Utils.arrayBufferToBase64(arrayBuffer)
  }

  public async xchacha20Decrypt(
    ciphertext: Base64String,
    nonce: HexString,
    key: HexString,
    assocData: Utf8String | Uint8Array
  ): Promise<Utf8String | null> {
    await this.ready
    if (nonce.length !== 48) {
      throw Error('Nonce must be 24 bytes')
    }
    try {
      return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        await Utils.base64ToArrayBuffer(ciphertext),
        assocData,
        await Utils.hexStringToArrayBuffer(nonce),
        await Utils.hexStringToArrayBuffer(key),
        'text'
      )
    } catch {
      return null
    }
  }
}
