  import '../dist/sncrypto.js';
import '../node_modules/chai/chai.js';
import './vendor/chai-as-promised-built.js';

const webCrypto = new SNWebCrypto();
const cryptoJs = new SNCryptoJS();

chai.use(chaiAsPromised);
var expect = chai.expect;

describe('webcrypto', function() {
  it('should be defined', function() {
    expect(window.crypto).to.not.be.null;
  });
});

describe('crypto operations', () => {

  const mk = "b6244a9c1189fc7b9fa70e89e6e342b94d742c6a86bbf4bea541aa9b1e2988fa";
  const ak = "15a54837a365c50d8c4dc3016defcc3458c9f654c3cba04053b42a68a55e99d1";

  it('generates valid uuid', () => {
    expect(webCrypto.generateUUIDSync().length).to.equal(36);
  });

  it('properly encodes base64', () => {
    var source = "hello world";
    var target = "aGVsbG8gd29ybGQ=";
    return expect(webCrypto.base64(source)).to.eventually.equal(target);
    return expect(cryptoJs.base64(source)).to.eventually.equal(target);
  });

  it('properly decodes base64', () => {
    var source = "aGVsbG8gd29ybGQ=";
    var target = "hello world";
    return expect(webCrypto.base64Decode(source)).to.eventually.equal(target);
    return expect(cryptoJs.base64Decode(source)).to.eventually.equal(target);
  });

  it('generates proper length generic key', async () => {
    var length = 256;
    let wc_result = await webCrypto.generateRandomKey(length);
    expect(wc_result.length).to.equal(length/4);

    let cj_result = await cryptoJs.generateRandomKey(length);
    expect(cj_result.length).to.equal(length/4);
  });

  it('cryptojs and webcrypto should generate same hmac signatures', async () => {
    var message = "hello world";
    var key = ak;
    let cryptojs = new SNCryptoJS();
    let webcrypto = new SNWebCrypto();
    let cryptoJsSignature = await cryptojs.hmac256(message, key);
    let webCryptoSignature = await webcrypto.hmac256(message, key);
    expect(cryptoJsSignature).to.equal(webCryptoSignature);
  })

  it('compares strings with timing safe comparison', async () => {
    let crypto = new SNPureCrypto();

    expect(crypto.timingSafeEqual("hello world", "hello world")).to.equal(true);

    expect(crypto.timingSafeEqual("helo world", "hello world")).to.equal(false);

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
  })

})
