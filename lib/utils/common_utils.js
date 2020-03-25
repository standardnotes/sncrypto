/* eslint-disable camelcase */
import {
  from_base64,
  to_base64,
  base64_variants,
  from_hex,
  to_hex,
  from_string,
  to_string,
} from '../libsodium';

/**
 * Libsodium's to_* functions take either a Buffer or String, but do not take raw buffers,
 * as may be returned by WebCrypto API.
 */

const arrayToBuffer = require('typedarray-to-buffer');
const Buffer = require('buffer/').Buffer;
export { Buffer };


const Format = {
  Utf8: 'utf8',
  Base64: 'base64',
  Hex: 'hex',
  Binary: 'binary'
};

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
  if(!isString(string)) {
    throw Error('Attempting to convert non-string to arrayBuffer');
  }
  return from_string(string);
}

/**
 * Converts an ArrayBuffer into a plain string
 * @access public
 * @param {ArrayBuffer} arrayBuffer
 * @returns {string} Plain string
 */
export async function arrayBufferToString(arrayBuffer) {
  return to_string(arrayBuffer);
}

/**
 * Converts an ArrayBuffer into a hex string
 * @access public
 * @param {ArrayBuffer} arrayBuffer
 * @returns {string} Hex string
 */
export async function arrayBufferToHexString(arrayBuffer) {
  return to_hex(Buffer.from(arrayBuffer));
}

/**
 * Converts a hex string into an ArrayBuffer
 * @access public
 * @param {string} hex - A hex string
 * @returns {ArrayBuffer}
 */
export async function hexStringToArrayBuffer(hex) {
  return from_hex(hex);
}

/**
 * Converts a base64 string into an ArrayBuffer
 * @access public
 * @param {string} base64 - A base64 string
 * @returns {ArrayBuffer}
 */
export async function base64ToArrayBuffer(base64) {
  return from_base64(base64, base64_variants.ORIGINAL);
}

/**
 * Converts an ArrayBuffer into a base64 string
 * @access public
 * @param {ArrayBuffer} buffer
 * @returns {string} base64 string
 */
export async function arrayBufferToBase64(arrayBuffer) {
  return to_base64(Buffer.from(arrayBuffer), base64_variants.ORIGINAL);
}

/**
 * Converts a hex string into a base64 string
 * @access public
 * @param {string} hex - A hex string
 * @returns {string} A base64 string
 */
export async function hexToBase64(hex) {
  return to_base64(from_hex(hex), base64_variants.ORIGINAL);
}

/**
 * Converts a base64 string into a hex string
 * @access public
 * @param {string} base64 - A base64 string
 * @returns {string} A hex string
 */
export async function base64ToHex(base64) {
  return to_hex(from_base64(base64, base64_variants.ORIGINAL));
}

/**
 * Converts a plain string into base64
 * @access public
 * @param {string} text - A plain string
 * @returns {string} A base64 encoded string
 */
export async function base64Encode(text) {
  return to_base64(text, base64_variants.ORIGINAL);
}

/**
 * Converts a base64 string into a plain string
 * @access public
 * @param {string} base64String - A base64 encoded string
 * @returns {string} A plain string
 */
export async function base64Decode(base64String) {
  return to_string(from_base64(base64String, base64_variants.ORIGINAL));
}

/**
 * Coerce input to a Buffer, throwing a TypeError if it cannot be coerced.
 * @param {string|Buffer|Uint8Array|Promise<Buffer>} stringOrBuffer
 * @returns {Buffer}
 */
export async function toBuffer(stringOrBuffer, format = Format.Binary) {
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