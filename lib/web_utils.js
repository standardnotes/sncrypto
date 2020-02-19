const Buffer = require('buffer/').Buffer;
export { Buffer };
const arrayToBuffer = require('typedarray-to-buffer');

export function getGlobalScope() {
  return typeof window !== 'undefined' ? window : (typeof global !== 'undefined' ? global : null);
}

export function ieOrEdge() {
  return (typeof document !== 'undefined' && document.documentMode) || /Edge/.test(navigator.userAgent);
}

export function isWebCryptoAvailable() {
  return !ieOrEdge() && getGlobalScope().crypto && getGlobalScope().crypto.subtle;
}

export function getSubtleCrypto() {
  return getGlobalScope().crypto ? getGlobalScope().crypto.subtle : null;
}

export function generateUUIDSync() {
  const globalScope = getGlobalScope();
  const crypto = globalScope.crypto || globalScope.msCrypto;
  if (crypto) {
    var buf = new Uint32Array(4);
    crypto.getRandomValues(buf);
    var idx = -1;
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
      idx++;
      var r = (buf[idx >> 3] >> ((idx % 8) * 4)) & 15;
      var v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  } else {
    var d = new Date().getTime();
    if (globalScope.performance && typeof globalScope.performance.now === "function") {
      d += performance.now(); // use high-precision timer if available
    }
    var uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
      var r = (d + Math.random() * 16) % 16 | 0;
      d = Math.floor(d / 16);
      return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
    return uuid;
  }
}

export async function stringToArrayBuffer(string) {
  // Using FileReader for higher performance amongst larger files
  return new Promise((resolve, reject) => {
    const blob = new Blob([string]);
    const reader = new FileReader();
    reader.onload = function (e) {
      resolve(e.target.result);
    };
    reader.readAsArrayBuffer(blob);
  });
}

export async function arrayBufferToString(arrayBuffer) {
  // Using FileReader for higher performance amongst larger files
  return new Promise((resolve, reject) => {
    const blob = new Blob([arrayBuffer]);
    const reader = new FileReader();
    reader.onload = function (e) {
      resolve(e.target.result);
    };
    reader.readAsText(blob);
  });
}

export async function arrayBufferToHexString(arrayBuffer) {
  const byteArray = new Uint8Array(arrayBuffer);
  let hexString = "";
  let nextHexByte;

  for (let i = 0; i < byteArray.byteLength; i++) {
    nextHexByte = byteArray[i].toString(16);
    if (nextHexByte.length < 2) {
      nextHexByte = "0" + nextHexByte;
    }
    hexString += nextHexByte;
  }
  return hexString;
}

export async function hexStringToArrayBuffer(hex) {
  const bytes = [];
  for (let c = 0; c < hex.length; c += 2) {
    bytes.push(parseInt(hex.substr(c, 2), 16));
  }
  return new Uint8Array(bytes);
}

export async function base64ToArrayBuffer(base64) {
  const binaryString = await base64Decode(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

export async function arrayBufferToBase64(buffer) {
  return new Promise((resolve, reject) => {
    var blob = new Blob([buffer], { type: 'application/octet-binary' });
    var reader = new FileReader();
    reader.onload = function (evt) {
      var dataurl = evt.target.result;
      resolve(dataurl.substr(dataurl.indexOf(',') + 1));
    };
    reader.readAsDataURL(blob);
  });
}

export async function hexToBase64(hex) {
  const buffer = Buffer.from(hex, 'hex');
  return buffer.toString('base64');
}

export async function base64ToHex(base64) {
  const buffer = Buffer.from(base64, 'base64');
  return buffer.toString('hex');
}

export function base64Encode(text) {
  return getGlobalScope().btoa(encodeURIComponent(text).replace(/%([0-9A-F]{2})/g,
    function toSolidBytes(match, p1) {
      return String.fromCharCode('0x' + p1);
    }));
}

export function base64Decode(base64String) {
  return getGlobalScope().atob(base64String);
}

export async function toHexBuffer(string) {
  return Buffer.from(string, 'hex');
}

/**
* Coerce input to a Buffer, throwing a TypeError if it cannot be coerced.
*
* @param {string|Buffer|Uint8Array|Promise<Buffer>} stringOrBuffer
* @returns {Buffer}
*/
export async function toBuffer(stringOrBuffer, format = 'binary') {
  if (Buffer.isBuffer(stringOrBuffer)) {
    return stringOrBuffer;
  } else if (stringOrBuffer === null) {
    return null;
  } else if (typeof (stringOrBuffer) === 'string') {
    return Buffer.from(stringOrBuffer, format);
  } else if (stringOrBuffer instanceof Uint8Array) {
    return arrayToBuffer(stringOrBuffer);
  } else if (stringOrBuffer instanceof Promise) {
    return stringOrBuffer;
  } else {
    throw new TypeError('Invalid type; string or buffer expected');
  }
}