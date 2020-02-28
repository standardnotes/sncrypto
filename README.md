# SNCrypto

Cryptographic primitives used by [SNJS](https://github.com/standardnotes/snjs).

## Supported Algorithms

- Argon2id (Libsodium.js)
- XChaCha20+Poly1305 (Libsodium.js)
- PBDKF2 (WebCrypto)
- AES-CBC (WebCrypto)
- HMAC SHA-256
- SHA256

## Building

1. `npm install`
2. `npm run start` or `npm run bundle`.

## Tests

Tests must be run in the browser due to WebCrypto dependency.

1. `node test-server.js`
2. Open browser to `http://localhost:9003/test/test.html`.