# SNCrypto

[![lerna](https://img.shields.io/badge/maintained%20with-lerna-cc00ff.svg)](https://lerna.js.org/)

Cryptographic primitives used by [SNJS](https://github.com/standardnotes/snjs).

## Installing

Depending on what package you want to type the following:
```
yarn add @standardnotes/sncrypto-common
```
or
```
yarn add @standardnotes/sncrypto-web
```

## Supported Algorithms

- Argon2id (Libsodium.js)
- XChaCha20+Poly1305 (Libsodium.js)
- PBDKF2 (WebCrypto)
- AES-CBC (WebCrypto)
- HMAC SHA-256
- SHA256

## Building

This repository is a Monorepo built with [Lerna](https://github.com/lerna/lerna). It consist of two packages: `@standardnotes/sncrypto-common` and `@standardnotes/sncrypto-web`.

In order to build the project run
```
yarn install --frozen-lockfile
yarn build
```

## Linting

To run linter on all packages run
```
yarn lint
```

## Testing

To run tests on all packages run
```
yarn test
```

## Publishing

In order to publish a new version of the package please make sure you have updated the `version` property in `package.json` of the specific package you want to publish.

## Tests

Tests must be run in the browser due to WebCrypto and WebAssembly dependency.

1. `node test-server.js`
2. Open browser to `http://localhost:9003/test/test.html`.
