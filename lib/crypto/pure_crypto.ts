import { generateUUIDSync } from "@Lib/utils";

/**
 * Abstract class with default implementations of basic helper functions.
 */
export abstract class SNPureCrypto {

  /** 
   * Derives a key from a password and salt using PBKDF2 via WebCrypto.
   * @param password - utf8 string
   * @param salt - utf8 string
   * @param iterations
   * @param length - In bits
   * @returns Hex string
   */
  public abstract async pbkdf2(
    password: string,
    salt: string,
    iterations: number,
    length: number
  ): Promise<string | null>;

  /** 
   * Generates a random key in hex format
   * @param bits - Length of key in bits
   * @returns A string key in hex format
   */
  public abstract async generateRandomKey(bits: number): Promise<string>;

  /** 
   * Encrypts a string using AES-CBC via WebCrypto.
   * @param plaintext
   * @param iv - In hex format
   * @param key - In hex format
   * @returns Ciphertext in Base64 format.
   */
  public abstract async aes256CbcEncrypt(plaintext: string, iv: string, key: string): Promise<string | null>;

  /**
   * Decrypts a string using AES-CBC via WebCrypto.
   * @param ciphertext - Base64 format
   * @param iv - In hex format
   * @param key - In hex format
   * @returns Plain utf8 string or null if decryption fails
   */
  public abstract async aes256CbcDecrypt(
    ciphertext: string,
    iv: string,
    key: string
  ): Promise<string | null>;

  /** 
   * Runs HMAC with SHA-256 on a message with key.
   * @param message - Plain utf8 string
   * @param key - In hex format
   * @returns Hex string or null if computation fails
   */
  public abstract async hmac256(message: string, key: string): Promise<string | null>;

  /** 
   * @param text - Plain utf8 string
   * @returns Hex string
   */
  public abstract async sha256(text: string): Promise<string>;

  /**
   * Use only for legacy applications.
   * @param text - Plain utf8 string
   * @returns Hex string
   */
  public abstract async unsafeSha1(text: string): Promise<string>;

  /**
   * Derives a key from a password and salt using 
   * argon2id (crypto_pwhash_ALG_DEFAULT).
   * @param password - Plain text string
   * @param salt - Salt in hex format
   * @param iterations - The algorithm's opslimit (recommended min 2)
   * @param bytes - The algorithm's memory limit (memlimit) (recommended min 67108864)
   * @param length - The output key length
   * @returns Derived key in hex format
   */
  public abstract async argon2(
    password: string,
    salt: string,
    iterations: number,
    bytes: number,
    length: number
  ): Promise<string>;

  /**
   * Encrypt a message (and associated data) with XChaCha20-Poly1305.
   * @param plaintext
   * @param nonce - In hex format
   * @param key - In hex format
   * @param assocData
   * @returns Base64 ciphertext string
   */
  public abstract async xchacha20Encrypt(
    plaintext: string,
    nonce: string,
    key: string,
    assocData: string
  ): Promise<string>;

  /**
   * Decrypt a message (and associated data) with XChaCha20-Poly1305
   * @param ciphertext
   * @param nonce - In hex format
   * @param key - In hex format
   * @param assocData
   * @returns Plain utf8 string or null if decryption fails
   */
  public abstract async xchacha20Decrypt(
    ciphertext: string,
    nonce: string,
    key: string,
    assocData: string
  ): Promise<string | null>;

  public deinit() {
    /** Optional override */
  }

  /**
   * Generates a UUID string syncronously.
   */
  public generateUUIDSync() {
    return generateUUIDSync();
  }

  /**
   * Generates a UUID string asyncronously.
   * Can be overriden by native platforms to provide async implementation
   */
  public async generateUUID() {
    return generateUUIDSync();
  }

  /**
   * Constant-time string comparison 
   * @param a
   * @param b
   */
  public timingSafeEqual(a: string, b: string) {
    const strA = String(a);
    let strB = String(b);
    const lenA = strA.length;
    let result = 0;

    if (lenA !== strB.length) {
      strB = strA;
      result = 1;
    }

    for (let i = 0; i < lenA; i++) {
      result |= (strA.charCodeAt(i) ^ strB.charCodeAt(i));
    }

    return result === 0;
  }
}
