/* eslint-disable no-unused-expressions */
/* eslint-disable no-undef */
import '../node_modules/chai/chai.js';
import './vendor/chai-as-promised-built.js';

chai.use(chaiAsPromised);
const expect = chai.expect;

describe('crypto operations', async function () {
  let webCrypto = new SNWebCrypto();

  after(() => {
    webCrypto.deinit();
    webCrypto = null;
  });

  it('webcrypto should be defined', function () {
    expect(window.crypto).to.not.be.null;
  });

  it('generates valid uuid', async function () {
    expect(webCrypto.generateUUIDSync().length).to.equal(36);
  });

  it('properly encodes base64', async function () {
    const source = "hello world 🌍";
    const target = "aGVsbG8gd29ybGQg8J+MjQ==";
    expect(await base64Encode(source)).to.equal(target);
  });

  it('properly decodes base64', async function () {
    const source = "aGVsbG8gd29ybGQg8J+MjQ==";
    const target = "hello world 🌍";
    expect(await base64Decode(source)).to.equal(target);
  });

  it('generates proper length generic key', async function () {
    const length = 256;
    const wcResult = await webCrypto.generateRandomKey(length);
    expect(wcResult.length).to.equal(length / 4);
  });

  it('compares strings with timing safe comparison', async function () {
    const crypto = new SNWebCrypto();
    expect(crypto.timingSafeEqual("hello world 🌍", "hello world 🌍")).to.equal(true);
    expect(crypto.timingSafeEqual("helo world 🌍", "hello world 🌍")).to.equal(false);
    expect(crypto.timingSafeEqual("", "a")).to.equal(false);
    expect(crypto.timingSafeEqual("", "")).to.equal(true);
    expect(crypto.timingSafeEqual(
      "2e1ee7920bb188a88f94bb912153befd83cc55cd",
      "2e1ee7920bb188a88f94bb912153befd83cc55cd")
    ).to.equal(true);
    expect(crypto.timingSafeEqual(
      "1e1ee7920bb188a88f94bb912153befd83cc55cd",
      "2e1ee7920bb188a88f94bb912153befd83cc55cd")
    ).to.equal(false);
    expect(crypto.timingSafeEqual(
      "2e1ee7920bb188a88f94bb912153befd83cc55cc",
      "2e1ee7920bb188a88f94bb912153befd83cc55cd")
    ).to.equal(false);
  });

  it('random key length', async function () {
    const key = await webCrypto.generateRandomKey(256);
    expect(key.length).to.equal(64);
  });

  it('pbkdf2 1', async function () {
    const password = "very_secure🔒";
    const salt = 'c3feb78823adce65c4ab024dab9c5cdcda5a04cdbd98f65eac0311dfa432d67b';
    const expected = 'bbb3d3af19dd1cbb901c958003faa55f193aad6a57fff30e51a62591bdc054d8';
    const result = await webCrypto.pbkdf2(
      password,
      salt,
      100000,
      256
    );
    expect(result).to.equal(expected);
  });

  it('pbkdf2 2', async function () {
    const password = "correct horse battery staple ✅";
    const salt = Buffer.from('808182838485868788898a8b8c8d8e8f', 'hex').toString('utf8');
    const expected = '795d83b18e55d860d3799f85a20f66ee17eb9dcf041df1d7a13fac30af7103d9';
    const result = await webCrypto.pbkdf2(
      password,
      salt,
      100000,
      256
    );
    expect(result).to.equal(expected);
  });

  it('aes cbc', async function () {
    const iv = await webCrypto.generateRandomKey(128);
    const key = await webCrypto.generateRandomKey(256);
    const text = 'hello world 🌍';
    const encrypted = await webCrypto.aes256CbcEncrypt(text, iv, key);
    const decrypted = await webCrypto.aes256CbcDecrypt(encrypted, iv, key);
    expect(decrypted).to.equal(text);
  });

  it('hmac 256', async function () {
    const text = 'hello world 🌍';
    const key = 'e802dc953f3f1f7b5db62409b74ac848559d4711c4e0047ecc5e312ad8ab8397';
    const hash = await webCrypto.hmac256(text, key);
    const expected = 'b63f94ee33a067ffac3ee97c7987dd3171dcdc747a322bb3f3ab890201c8e6f9';
    expect(hash).to.equal(expected);
  });

  it('sha256', async function () {
    const text = 'hello world 🌍';
    const hash = await webCrypto.sha256(text);
    const expected = '1e71fe32476da1ff115b44dfd74aed5c90d68a1d80a2033065e30cff4335211a';
    expect(hash).to.equal(expected);
  });

  it('sha1', async function () {
    const text = 'hello world 🌍';
    const hash = await webCrypto.unsafeSha1(text);
    const expected = '0818667aed20ac104ca8f300f8df9753e1937983';
    expect(hash).to.equal(expected);
  });

  it('argon2 predefined salt', async function () {
    const password = "correct horse battery staple ✅";
    const salt = Buffer.from('808182838485868788898a8b8c8d8e8f', 'hex');
    const bytes = 67108864;
    const length = 16;
    const iterations = 2;
    const result = await webCrypto.argon2(
      password,
      salt,
      iterations,
      bytes,
      length
    );
    const expectedResult = "0aded8d318adc2fcf782291b5ee14239";
    expect(result).to.equal(expectedResult);
  });

  it('argon2 generated salt', async function () {
    const rawSalt = await webCrypto.sha256(['foo', 'bar'].join(":"));
    const truncatedSalt = rawSalt.substring(0, rawSalt.length / 2);
    const password = "foobarfoo🔒";
    const bytes = 67108864;
    const length = 32;
    const iterations = 5;
    const result = await webCrypto.argon2(
      password,
      truncatedSalt,
      iterations,
      bytes,
      length
    );
    const expected = "ab795e298e4ee8c0a6175f099c89870c4f50512c54f79863a4c9566502b83fd9";
    expect(result).to.equal(expected);
  });

  it('xchacha20 encrypt/decrypt', async function () {
    const key = await webCrypto.generateRandomKey(256);
    const nonce = await webCrypto.generateRandomKey(192);
    const plaintext = 'hello world 🌍';
    const aad = JSON.stringify({ uuid: '123🎤' });
    const ciphertext = await webCrypto.xchacha20Encrypt(
      plaintext,
      nonce,
      key,
      aad
    );
    const decrypted = await webCrypto.xchacha20Decrypt(
      ciphertext,
      nonce,
      key,
      aad
    );
    expect(decrypted).to.equal(plaintext);
  });

  it('xchacha20 should fail with nonmatching aad', async function () {
    const key = await webCrypto.generateRandomKey(256);
    const nonce = await webCrypto.generateRandomKey(192);
    const plaintext = 'hello world 🌍';
    const ciphertext = await webCrypto.xchacha20Encrypt(
      plaintext,
      nonce,
      key,
      JSON.stringify({ uuid: 'foo🎲' })
    );
    const result = await webCrypto.xchacha20Decrypt(
      ciphertext,
      nonce,
      key,
      JSON.stringify({ uuid: 'bar🎲' })
    );
    expect(result).to.not.be.ok;
  });

  it('xchacha predefined string', async function () {
    /** Based on same Sodium-Plus test */
    const plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.☀️";
    const assocData = Buffer.from('50515253c0c1c2c3c4c5c6c7', 'hex');
    const nonce = '404142434445464748494a4b4c4d4e4f5051525354555657';
    const key = '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f';
    const ciphertext = await webCrypto.xchacha20Encrypt(plaintext, nonce, key, assocData);
    const expected = "vW0XnT6D1DuVdleUk8DpOVcqFwAlK_rMvtKQLCE5bLtzHH8bC0qmRAvzqC9O2n45rmTGcIxUwhbLlrcuEhO0Ui-Mm6QNtdlFsRtpuYLBu54_P6wrw2lIj3ayODVl0__5IflmTJdjfal2iBL2FcaLE7UuKKs24MrJt7GFZzfvrTqlSB41CqFHrQ";
    expect(ciphertext).to.equal(expected);
    const decrypted = await webCrypto.xchacha20Decrypt(ciphertext, nonce, key, assocData);
    expect(decrypted).to.equal(plaintext);
  });
});
