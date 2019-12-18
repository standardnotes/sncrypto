import { SNAbstractCrypto } from './abstract_crypto';

export class SNReactNativeCrypto extends SNAbstractCrypto {

  // Called by React Native to dynamically set Aes and base64 module instances.
  setNativeModules({aes, base64}) {
    this.Aes = aes;
    this.base64 = base64;
  }

  async generateUUID() {
    return this.Aes.randomUuid().then((uuid) => {
      return uuid.toLowerCase();
    });
  }

  async pbkdf2(password, salt, cost, length) {
    return this.Aes.pbkdf2(password, salt, cost, length).then(key => {
      return key;
    });
  }

  async generateRandomKey(length) {
    return this.Aes.randomKey(length/8);
  }

  async generateRandomEncryptionKey() {
    return this.generateRandomKey(512);
  }

  async base64(text) {
    return this.base64.encode(text);
  }

  async base64Decode(base64String) {
    return this.base64.decode(base64String);
  }

  async sha256(text) {
    return this.Aes.sha256(text);
  }

  async hmac256(message, key) {
    return this.Aes.hmac256(message, key);
  }
}
