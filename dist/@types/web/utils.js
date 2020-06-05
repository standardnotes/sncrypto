/* eslint-disable camelcase */
import { from_base64, to_base64, base64_variants, from_hex, to_hex, from_string, to_string, ready } from './libsodium';
/**
 * Libsodium's to_* functions take either a Buffer or String, but do not take raw buffers,
 * as may be returned by WebCrypto API.
 */
import arrayToBuffer from 'typedarray-to-buffer';
import { Buffer } from 'buffer';
export { Buffer };
export var Format;
(function (Format) {
    Format["Utf8"] = "utf8";
    Format["Base64"] = "base64";
    Format["Hex"] = "hex";
    Format["Binary"] = "binary";
})(Format || (Format = {}));
;
/**
 * Returns `window` if available, or `global` if supported in environment.
 */
export function getGlobalScope() {
    return window;
}
/**
 * Determines whether we are in an Internet Explorer or Edge environment
 * @access public
 */
export function ieOrEdge() {
    return (typeof document !== 'undefined' && document.documentMode) || /Edge/.test(navigator.userAgent);
}
/**
 * Returns true if WebCrypto is available
 * @access public
 */
export function isWebCryptoAvailable() {
    return !ieOrEdge() && getGlobalScope().crypto && !!getGlobalScope().crypto.subtle;
}
/**
 * Returns the WebCrypto instance
 * @access public
 */
export function getSubtleCrypto() {
    return getGlobalScope().crypto ? getGlobalScope().crypto.subtle : null;
}
/**
 * Generates a UUID syncronously
 * @access public
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
    }
    else {
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
 * Constant-time string comparison
 * @param a
 * @param b
 */
export function timingSafeEqual(a, b) {
    const strA = String(a);
    let strB = String(b);
    const lenA = strA.length;
    let result = 0;
    if (lenA !== strB.length) {
        strB = strA;
        result = 1;
    }
    for (let i = 0; i < lenA; i++) {
        result |= (strA.charCodeAt(i) ^ strB.charCodeAt(i));
    }
    return result === 0;
}
/**
 * Determines if the input value is a string
 */
export function isString(value) {
    return typeof value === 'string' || value instanceof String;
}
/**
 * Converts a plain string into an ArrayBuffer
 * @param {string} string - A plain string
 */
export async function stringToArrayBuffer(string) {
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
export async function arrayBufferToString(arrayBuffer) {
    await ready;
    return to_string(arrayBuffer);
}
/**
 * Converts an ArrayBuffer into a hex string
 * @param arrayBuffer
 */
export async function arrayBufferToHexString(arrayBuffer) {
    await ready;
    return to_hex(Buffer.from(arrayBuffer));
}
/**
 * Converts a hex string into an ArrayBuffer
 * @access public
 * @param hex - A hex string
 */
export async function hexStringToArrayBuffer(hex) {
    await ready;
    return from_hex(hex);
}
/**
 * Converts a base64 string into an ArrayBuffer
 * @param base64 - A base64 string
 */
export async function base64ToArrayBuffer(base64) {
    await ready;
    return from_base64(base64, base64_variants.ORIGINAL);
}
/**
 * Converts an ArrayBuffer into a base64 string
 * @param buffer
 */
export async function arrayBufferToBase64(arrayBuffer) {
    await ready;
    return to_base64(Buffer.from(arrayBuffer), base64_variants.ORIGINAL);
}
/**
 * Converts a hex string into a base64 string
 * @param hex - A hex string
 */
export async function hexToBase64(hex) {
    await ready;
    return to_base64(from_hex(hex), base64_variants.ORIGINAL);
}
/**
 * Converts a base64 string into a hex string
 * @param base64 - A base64 string
 */
export async function base64ToHex(base64) {
    await ready;
    return to_hex(from_base64(base64, base64_variants.ORIGINAL));
}
/**
 * Converts a plain string into base64
 * @param text - A plain string
 * @returns  A base64 encoded string
 */
export async function base64Encode(text) {
    await ready;
    return to_base64(text, base64_variants.ORIGINAL);
}
/**
 * Converts a base64 string into a plain string
 * @param base64String - A base64 encoded string
 * @returns A plain string
 */
export async function base64Decode(base64String) {
    await ready;
    return to_string(from_base64(base64String, base64_variants.ORIGINAL));
}
/**
 * Coerce input to a Buffer, throwing a TypeError if it cannot be coerced.
 * @param stringOrBuffer
 * @returns
 */
export async function toBuffer(stringOrBuffer, format = Format.Binary) {
    if (Buffer.isBuffer(stringOrBuffer)) {
        return stringOrBuffer;
    }
    else if (stringOrBuffer === null) {
        return null;
    }
    else if (typeof (stringOrBuffer) === 'string') {
        return Buffer.from(stringOrBuffer, format);
    }
    else if (stringOrBuffer instanceof Uint8Array) {
        return arrayToBuffer(stringOrBuffer);
    }
    else {
        throw new TypeError('Invalid type; string or buffer expected');
    }
}
