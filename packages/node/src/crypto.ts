/* eslint-disable @typescript-eslint/no-unused-vars */
import {
  Aes256GcmEncrypted,
  HexString,
  SnCryptoAes256Gcm,
  Utf8String,
} from '@standardnotes/sncrypto-common'
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto'

export class SnCryptoNode implements SnCryptoAes256Gcm {
  public async aes256GcmEncrypt(
    plaintext: HexString,
    iv: HexString,
    key: HexString,
    aad: HexString = '',
  ): Promise<Aes256GcmEncrypted> {
    const dataBuffer = Buffer.from(plaintext, 'hex')
    const ivBuffer = Buffer.from(iv, 'hex')
    const keyBuffer = Buffer.from(key, 'hex')
    const cipher = createCipheriv('aes-256-gcm', keyBuffer, ivBuffer)
    const aadBuffer = Buffer.from(aad, 'hex')
    cipher.setAAD(aadBuffer)

    const ciphertext = Buffer.concat([
      cipher.update(dataBuffer),
      cipher.final()
    ]).toString('base64')

    const tag = cipher.getAuthTag().toString('hex')

    return {iv, tag, ciphertext}
  }

  public async aes256GcmDecrypt(
    encrypted: Aes256GcmEncrypted,
    key: HexString,
  ): Promise<Utf8String | null> {
    const {iv, tag, ciphertext} = encrypted

    const decipher = createDecipheriv(
      'aes-256-gcm', 
      Buffer.from(key, 'hex'), 
      Buffer.from(iv, 'hex'),
    )
    decipher.setAuthTag(Buffer.from(tag, 'hex'))

    const decrypted = decipher.update(
      Buffer.from(ciphertext, 'base64'), 
      undefined, 
      'utf8',
    ) + decipher.final('utf8')

    return decrypted
  }

  public async generateRandomKey(bits: number): Promise<HexString> {
    const bytes = bits / 8
    const buf = randomBytes(bytes)
    return buf.toString('hex')
  }
}
