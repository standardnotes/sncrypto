/* eslint-disable camelcase */
import {
  from_base64,
  to_base64,
  base64_variants,
  from_hex,
  to_hex,
  from_string,
  to_string,
  ready
} from '../libsodium';

/**
 * Libsodium's to_* functions take either a Buffer or String, but do not take raw buffers,
 * as may be returned by WebCrypto API.
 */

import arrayToBuffer from 'typedarray-to-buffer';
import { Buffer } from 'buffer';
export { Buffer };

export enum Format {
  Utf8 = 'utf8',
  Base64 = 'base64',
  Hex = 'hex',
  Binary = 'binary'
};

/**
 * Determines if the input value is a string
 */
export function isString(value: any) {
  return typeof value === 'string' || value instanceof String;
}

/**
 * Converts a plain string into an ArrayBuffer
 * @param {string} string - A plain string
 */
export async function stringToArrayBuffer(string: string) {
  if (!isString(string)) {
    throw Error('Attempting to convert non-string to arrayBuffer');
  }
  await ready;
  return from_string(string);
}

/**
 * Converts an ArrayBuffer into a plain string
 * @param {ArrayBuffer} arrayBuffer
 */
export async function arrayBufferToString(arrayBuffer: ArrayBuffer) {
  await ready;
  return to_string(arrayBuffer as Uint8Array);
}

/**
 * Converts an ArrayBuffer into a hex string
 * @param arrayBuffer
 */
export async function arrayBufferToHexString(arrayBuffer: ArrayBuffer) {
  await ready;
  return to_hex(Buffer.from(arrayBuffer));
}

/**
 * Converts a hex string into an ArrayBuffer
 * @access public
 * @param hex - A hex string
 */
export async function hexStringToArrayBuffer(hex: string) {
  await ready;
  return from_hex(hex);
}

/**
 * Converts a base64 string into an ArrayBuffer
 * @param base64 - A base64 string
 */
export async function base64ToArrayBuffer(base64: string) {
  await ready;
  return from_base64(base64, base64_variants.ORIGINAL);
}

/**
 * Converts an ArrayBuffer into a base64 string
 * @param buffer
 */
export async function arrayBufferToBase64(arrayBuffer: ArrayBuffer) {
  await ready;
  return to_base64(Buffer.from(arrayBuffer), base64_variants.ORIGINAL);
}

/**
 * Converts a hex string into a base64 string
 * @param hex - A hex string
 */
export async function hexToBase64(hex: string) {
  await ready;
  return to_base64(from_hex(hex), base64_variants.ORIGINAL);
}

/**
 * Converts a base64 string into a hex string
 * @param base64 - A base64 string
 */
export async function base64ToHex(base64: string) {
  await ready;
  return to_hex(from_base64(base64, base64_variants.ORIGINAL));
}

/**
 * Converts a plain string into base64
 * @param text - A plain string
 * @returns  A base64 encoded string
 */
export async function base64Encode(text: string) {
  await ready;
  return to_base64(text, base64_variants.ORIGINAL);
}

/**
 * Converts a base64 string into a plain string
 * @param base64String - A base64 encoded string
 * @returns A plain string
 */
export async function base64Decode(base64String: string) {
  await ready;
  return to_string(from_base64(base64String, base64_variants.ORIGINAL));
}

/**
 * Coerce input to a Buffer, throwing a TypeError if it cannot be coerced.
 * @param stringOrBuffer
 * @returns
 */
export async function toBuffer(
  stringOrBuffer: string | ArrayBuffer,
  format = Format.Binary
) {
  if (Buffer.isBuffer(stringOrBuffer)) {
    return stringOrBuffer;
  } else if (stringOrBuffer === null) {
    return null;
  } else if (typeof (stringOrBuffer) === 'string') {
    return Buffer.from(stringOrBuffer, format);
  } else if (stringOrBuffer instanceof Uint8Array) {
    return arrayToBuffer(stringOrBuffer);
  } else {
    throw new TypeError('Invalid type; string or buffer expected');
  }
}