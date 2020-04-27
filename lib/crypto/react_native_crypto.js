import { SNAbstractCrypto } from './abstract_crypto';

export class SNReactNativeCrypto extends SNAbstractCrypto {

  // Called by React Native to dynamically set Aes and base64 module instances.
  setNativeModules({aes, base64}) {
    this.Aes = aes;
    this.base64Instance = base64;
  }

  async generateUUID() {
    const uuid = await this.Aes.randomUuid();
    return uuid.toLowerCase();
  }

  async pbkdf2(password, salt, cost, length) {
    const key = await this.Aes.pbkdf2(password, salt, cost, length);
    return key;
  }

  async generateRandomKey(length) {
    return this.Aes.randomKey(length/8);
  }

  async generateRandomEncryptionKey() {
    return this.generateRandomKey(512);
  }

  async base64(text) {
    return this.base64Instance.encode(text);
  }

  async base64Decode(base64String) {
    return this.base64Instance.decode(base64String);
  }

  async sha256(text) {
    return this.Aes.sha256(text);
  }

  async hmac256(message, key) {
    return this.Aes.hmac256(message, key);
  }

  async aes256CbcDecrypt(ciphertext, keyData, ivData) {
    return this.Aes.decrypt(ciphertext, keyData, ivData);
  }

  async aes256CbcEncrypt(text, keyData, ivData) {
    const result = await this.Aes.encrypt(text, keyData, ivData);
    console.log(result);
    return result.cipher;
  }
}
