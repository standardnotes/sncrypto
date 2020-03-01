const arrayToBuffer = require('typedarray-to-buffer');
const Buffer = require('buffer/').Buffer;
export { Buffer };

/**
 * Returns `window` if available, or `global` if supported in environment.
 * @returns {object|null}
 */
export function getGlobalScope() {
  return typeof window !== 'undefined' ? window : (typeof global !== 'undefined' ? global : null);
}

/**
 * Determines whether we are in an Internet Explorer or Edge environment
 * @access public
 * @returns {boolean}
 */
export function ieOrEdge() {
  return (typeof document !== 'undefined' && document.documentMode) || /Edge/.test(navigator.userAgent);
}

/**
 * Returns true if WebCrypto is available
 * @access public
 * @returns {boolean}
 */
export function isWebCryptoAvailable() {
  return !ieOrEdge() && getGlobalScope().crypto && !!getGlobalScope().crypto.subtle;
}

/**
 * Returns the WebCrypto instance
 * @access public
 * @returns {object}
 */
export function getSubtleCrypto() {
  return getGlobalScope().crypto ? getGlobalScope().crypto.subtle : null;
}

/**
 * Generates a UUID syncronously
 * @access public
 * @returns {string}
 */
export function generateUUIDSync() {
  const globalScope = getGlobalScope();
  const crypto = globalScope.crypto || globalScope.msCrypto;
  if (crypto) {
    const buf = new Uint32Array(4);
    crypto.getRandomValues(buf);
    let idx = -1;
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
      idx++;
      const r = (buf[idx >> 3] >> ((idx % 8) * 4)) & 15;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  } else {
    let d = new Date().getTime();
    if (globalScope.performance && typeof globalScope.performance.now === "function") {
      d += performance.now(); // use high-precision timer if available
    }
    const uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
      const r = (d + Math.random() * 16) % 16 | 0;
      d = Math.floor(d / 16);
      return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
    return uuid;
  }
}

/**
 * Determines if the input value is a string
 * @access public
 * @returns {boolean}
 */
export function isString(value) {
  return typeof value === 'string' || value instanceof String;
}

/**
 * Converts a plain string into an ArrayBuffer
 * @access public
 * @param {string} string - A plain string
 * @returns {ArrayBuffer}
 */
export async function stringToArrayBuffer(string) {
  /* Using FileReader for higher performance amongst larger files */
  return new Promise((resolve, reject) => {
    const blob = new Blob([string]);
    const reader = new FileReader();
    reader.onload = function (e) {
      resolve(e.target.result);
    };
    reader.readAsArrayBuffer(blob);
  });
}

/**
 * Converts an ArrayBuffer into a plain string
 * @access public
 * @param {ArrayBuffer} arrayBuffer
 * @returns {string} Plain string
 */
export async function arrayBufferToString(arrayBuffer) {
  /* Using FileReader for higher performance amongst larger files */
  return new Promise((resolve, reject) => {
    const blob = new Blob([arrayBuffer]);
    const reader = new FileReader();
    reader.onload = function (e) {
      resolve(e.target.result);
    };
    reader.readAsText(blob);
  });
}

/**
 * Converts an ArrayBuffer into a hex string
 * @access public
 * @param {ArrayBuffer} arrayBuffer
 * @returns {string} Hex string
 */
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

/**
 * Converts a hex string into an ArrayBuffer
 * @access public
 * @param {string} hex - A hex string
 * @returns {ArrayBuffer}
 */
export async function hexStringToArrayBuffer(hex) {
  const bytes = [];
  for (let c = 0; c < hex.length; c += 2) {
    bytes.push(parseInt(hex.substr(c, 2), 16));
  }
  return new Uint8Array(bytes);
}

/**
 * Converts a base64 string into an ArrayBuffer
 * @access public
 * @param {string} base64 - A base64 string
 * @returns {ArrayBuffer}
 */
export async function base64ToArrayBuffer(base64) {
  const binaryString = await base64Decode(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Converts an ArrayBuffer into a base64 string
 * @access public
 * @param {ArrayBuffer} buffer
 * @returns {string} base64 string
 */
export async function arrayBufferToBase64(buffer) {
  return new Promise((resolve, reject) => {
    const blob = new Blob([buffer], { type: 'application/octet-binary' });
    const reader = new FileReader();
    reader.onload = function (evt) {
      const dataurl = evt.target.result;
      resolve(dataurl.substr(dataurl.indexOf(',') + 1));
    };
    reader.readAsDataURL(blob);
  });
}

/**
 * Converts a hex string into a base64 string
 * @access public
 * @param {string} hex - A hex string
 * @returns {string} A base64 string
 */
export async function hexToBase64(hex) {
  const buffer = Buffer.from(hex, 'hex');
  return buffer.toString('base64');
}

/**
 * Converts a base64 string into a hex string
 * @access public
 * @param {string} base64 - A base64 string
 * @returns {string} A hex string
 */
export async function base64ToHex(base64) {
  const buffer = Buffer.from(base64, 'base64');
  return buffer.toString('hex');
}

/**
 * Converts a plain string into base64
 * @access public
 * @param {string} text - A plain string
 * @returns {string} A base64 encoded string
 */
export function base64Encode(text) {
  return getGlobalScope().btoa(encodeURIComponent(text).replace(/%([0-9A-F]{2})/g,
    function toSolidBytes(match, p1) {
      return String.fromCharCode('0x' + p1);
    }));
}

/**
 * Converts a base64 string into a plain string
 * @access public
 * @param {string} base64String - A base64 encoded string
 * @returns {string} A plain string
 */
export function base64Decode(base64String) {
  return getGlobalScope().atob(base64String);
}

/**
 * Coerce input to a Buffer, throwing a TypeError if it cannot be coerced.
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