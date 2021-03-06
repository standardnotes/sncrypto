/* eslint-disable camelcase */
import {
  base64_variants,
  from_base64,
  from_hex,
  from_string,
  ready,
  to_base64,
  to_hex,
  to_string
} from './libsodium'

const SN_BASE64_VARIANT = base64_variants.ORIGINAL

/**
 * Libsodium's to_* functions take either a Buffer or String, but do not take raw buffers,
 * as may be returned by WebCrypto API.
 */

declare global {
  interface Document {
    documentMode?: string;
  }
  interface Window {
    msCrypto?: Crypto
  }
}

/**
 * Returns `window` if available, or `global` if supported in environment.
 */
export function getGlobalScope(): Window & typeof globalThis {
  return window
}

/**
 * Determines whether we are in an Internet Explorer or Edge environment
 * @access public
 */
export function ieOrEdge(): boolean {
  return (typeof document !== 'undefined' && !!document.documentMode) || /Edge/.test(navigator.userAgent)
}

/**
 * Returns true if WebCrypto is available
 * @access public
 */
export function isWebCryptoAvailable(): boolean {
  return !ieOrEdge() && getGlobalScope().crypto && !!getGlobalScope().crypto.subtle
}

/**
 * Returns the WebCrypto instance
 * @access public
 */
export function getSubtleCrypto(): SubtleCrypto {
  if (!getGlobalScope().crypto) {
    throw Error('Could not obtain SubtleCrypto instance')
  }

  return getGlobalScope().crypto.subtle
}

/**
 * Generates a UUID syncronously
 * @access public
 */
export function generateUUIDSync(): string {
  const globalScope = getGlobalScope()
  const crypto = globalScope.crypto || globalScope.msCrypto
  if (crypto) {
    const buf = new Uint32Array(4)
    crypto.getRandomValues(buf)
    let idx = -1
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
      idx++
      const r = (buf[idx >> 3] >> ((idx % 8) * 4)) & 15
      const v = c === 'x' ? r : (r & 0x3 | 0x8)
      return v.toString(16)
    })
  } else {
    let d = new Date().getTime()
    if (globalScope.performance && typeof globalScope.performance.now === "function") {
      d += performance.now() // use high-precision timer if available
    }
    const uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
      const r = (d + Math.random() * 16) % 16 | 0
      d = Math.floor(d / 16)
      return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16)
    })
    return uuid
  }
}

/**
 * Converts a plain string into an ArrayBuffer
 * @param {string} string - A plain string
 */
export async function stringToArrayBuffer(string: string): Promise<Uint8Array> {
  await ready
  return from_string(string)
}

/**
 * Converts an ArrayBuffer into a plain string
 * @param {ArrayBuffer} arrayBuffer
 */
export async function arrayBufferToString(arrayBuffer: ArrayBuffer): Promise<string> {
  await ready
  return to_string(arrayBuffer as Uint8Array)
}

/**
 * Converts an ArrayBuffer into a hex string
 * @param arrayBuffer
 */
export async function arrayBufferToHexString(arrayBuffer: ArrayBuffer): Promise<string> {
  await ready
  return to_hex(Buffer.from(arrayBuffer))
}

/**
 * Converts a hex string into an ArrayBuffer
 * @access public
 * @param hex - A hex string
 */
export async function hexStringToArrayBuffer(hex: string): Promise<Uint8Array> {
  await ready
  return from_hex(hex)
}

/**
 * Converts a base64 string into an ArrayBuffer
 * @param base64 - A base64 string
 */
export async function base64ToArrayBuffer(base64: string): Promise<Uint8Array> {
  await ready
  return from_base64(base64, SN_BASE64_VARIANT)
}

/**
 * Converts an ArrayBuffer into a base64 string
 * @param buffer
 */
export async function arrayBufferToBase64(arrayBuffer: ArrayBuffer): Promise<string> {
  await ready
  return to_base64(Buffer.from(arrayBuffer), SN_BASE64_VARIANT)
}

/**
 * Converts a hex string into a base64 string
 * @param hex - A hex string
 */
export async function hexToBase64(hex: string): Promise<string> {
  await ready
  return to_base64(from_hex(hex), SN_BASE64_VARIANT)
}

/**
 * Converts a base64 string into a hex string
 * @param base64 - A base64 string
 */
export async function base64ToHex(base64: string): Promise<string> {
  await ready
  return to_hex(from_base64(base64, SN_BASE64_VARIANT))
}

/**
 * Converts a plain string into base64
 * @param text - A plain string
 * @returns  A base64 encoded string
 */
export async function base64Encode(text: string): Promise<string> {
  await ready
  return to_base64(text, SN_BASE64_VARIANT)
}

/**
 * Converts a base64 string into a plain string
 * @param base64String - A base64 encoded string
 * @returns A plain string
 */
export async function base64Decode(base64String: string): Promise<string> {
  await ready
  return to_string(from_base64(base64String, SN_BASE64_VARIANT))
}
