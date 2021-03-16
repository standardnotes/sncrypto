/* eslint-disable @typescript-eslint/no-unused-vars */
import {
  Aes256GcmEncrypted,
  Aes256GcmInput,
  Base64String,
  HexString,
  SNPureCrypto,
  Utf8String,
  timingSafeEqual
} from '@standardnotes/sncrypto-common'
import { createCipheriv, createDecipheriv } from 'crypto'

export class SNCryptoNode implements SNPureCrypto {
  public async aes256GcmEncrypt({
    input: {
      plaintext,
      iv,
      key,
      aad = '',
      encoding = 'base64',
    },
    outputEncoding = 'base64',
  }: {
    input: Aes256GcmInput,
    outputEncoding: BufferEncoding,
  }): 
  Promise<Aes256GcmEncrypted> {
    const dataBuffer = Buffer.from(plaintext, encoding)
    const ivBuffer = Buffer.from(iv, encoding)
    const keyBuffer = Buffer.from(key, encoding)
    const cipher = createCipheriv('aes-256-gcm', keyBuffer, ivBuffer)
    const aadBuffer = Buffer.from(aad, encoding)
    cipher.setAAD(aadBuffer)

    const ciphertext = Buffer.concat([
      cipher.update(dataBuffer),
      cipher.final()
    ]).toString(outputEncoding)

    const tag = cipher.getAuthTag().toString(outputEncoding)

    return {iv, tag, ciphertext, encoding: outputEncoding}
  }

  public async aes256GcmDecrypt({
    encrypted,
    key,
  }: {
    encrypted: Aes256GcmEncrypted,
    key: HexString,
  }): Promise<Utf8String | null> {
    const {iv, tag, ciphertext, encoding} = encrypted

    const decipher = createDecipheriv('aes-256-gcm', key, iv)
    decipher.setAuthTag(Buffer.from(tag, encoding))

    const decrypted = decipher.update(Buffer.from(ciphertext, encoding), undefined, 'utf8') + decipher.final('utf8')

    return decrypted
  }

  public generateUUIDSync(): string {
    throw new Error('Method not implemented.')
  }

  public async generateUUID(): Promise<string> {
    throw new Error('Method not implemented.')
  }

  public timingSafeEqual(a: string, b: string): boolean {
    return timingSafeEqual(a, b)
  }

  public async base64Encode(text: Utf8String): Promise<string> {
    throw new Error('Method not implemented.')
  }

  public async base64Decode(base64String: Base64String): Promise<string> {
    throw new Error('Method not implemented.')
  }

  public async pbkdf2(
    password: Utf8String,
    salt: Utf8String,
    iterations: number,
    length: number
  ): Promise<HexString | null> {
    throw new Error('Method not implemented.')
  }

  public async generateRandomKey(bits: number): Promise<string> {
    throw new Error('Method not implemented.')
  }

  public async aes256CbcEncrypt(
    plaintext: Utf8String,
    iv: HexString,
    key: HexString
  ): Promise<Base64String> {
    throw new Error('Method not implemented.')
  }

  public async aes256CbcDecrypt(
    ciphertext: Base64String,
    iv: HexString,
    key: HexString
  ): Promise<Utf8String | null> {
    throw new Error('Method not implemented.')
  }

  public async hmac256(
    message: Utf8String,
    key: HexString
  ): Promise<HexString | null> {
    throw new Error('Method not implemented.')
  }

  public async sha256(text: string): Promise<string> {
    throw new Error('Method not implemented.')
  }

  public async unsafeSha1(text: string): Promise<string> {
    throw new Error('Method not implemented.')
  }

  public async argon2(
    password: Utf8String,
    salt: HexString,
    iterations: number,
    bytes: number,
    length: number
  ): Promise<HexString> {
    throw new Error('Method not implemented.')
  }

  public async xchacha20Encrypt(
    plaintext: Utf8String,
    nonce: HexString,
    key: HexString,
    assocData: Utf8String
  ): Promise<Base64String> {
    throw new Error('Method not implemented.')
  }

  public async xchacha20Decrypt(
    ciphertext: Base64String,
    nonce: HexString,
    key: HexString,
    assocData: Utf8String | Uint8Array
  ): Promise<Utf8String | null> {
    throw new Error('Method not implemented.')
  }
}
