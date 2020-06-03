import { SNPureCrypto } from "./pure_crypto";
import Sodium from 'react-native-sodium';
import Aes from 'react-native-aes-crypto';
export declare class SNReactNativeCrypto extends SNPureCrypto {
    sodium: typeof Sodium;
    Aes: typeof Aes;
    /**
     * It is required to call this from react native to set native modules references
     * @param sodium - react-native-sodium reference
     * @param aes - react-native-aes-crypto reference
    */
    setNativeModules(sodium: typeof Sodium, aes: typeof Aes): void;
    pbkdf2(password: string, salt: string, iterations: number, length: number): Promise<string | null>;
    generateRandomKey(bits: number): Promise<string>;
    aes256CbcEncrypt(plaintext: string, iv: string, key: string): Promise<string | null>;
    aes256CbcDecrypt(ciphertext: string, iv: string, key: string): Promise<string | null>;
    hmac256(message: string, key: string): Promise<string | null>;
    sha256(text: string): Promise<string>;
    unsafeSha1(text: string): Promise<string>;
    argon2(password: string, salt: string, iterations: number, bytes: number, length: number): Promise<string>;
    xchacha20Encrypt(plaintext: string, nonce: string, key: string, assocData: string): Promise<string>;
    xchacha20Decrypt(ciphertext: string, nonce: string, key: string, assocData: string): Promise<string | null>;
    /**
      * Not implemented in SNReactNativeCrypto
    */
    generateUUIDSync(): string;
    generateUUID(): Promise<string>;
    base64Encode(text: string): Promise<string>;
    base64Decode(base64String: string): Promise<string>;
}
