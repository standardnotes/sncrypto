import { HexString, Utf8String } from "."
import { Base64String } from "./pure_crypto"

export type Aes256GcmEncrypted = {
  iv: HexString, 
  tag: HexString, 
  ciphertext: Base64String,
}

export interface SnCryptoAes256Gcm {
  /**
   * // todo: update doc
   * Encrypts a string using AES-GCM.
   * @param plaintext
   * @param iv - In hex format
   * @param key - In hex format
   * @param aad
   * @param inputEncoding -- 
   * @returns Ciphertext in Base64 format.
   */
  aes256GcmEncrypt(
    plaintext: Utf8String,
    iv: HexString,
    key: HexString,
    aad?: HexString,
  ): Promise<Aes256GcmEncrypted>

  /**
   * // todo: update doc
   * Decrypts a string using AES-GCM.
   * @param ciphertext - Base64 format
   * @param iv - In hex format
   * @param key - In hex format
   * @returns Plain utf8 string or null if decryption fails
   */
  aes256GcmDecrypt(
    encrypted: Aes256GcmEncrypted,
    key: HexString,
  ): Promise<Utf8String | null>
}
