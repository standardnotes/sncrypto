/// <reference types="node" />
import { Buffer } from 'buffer';
export { Buffer };
declare global {
    interface Document {
        documentMode?: any;
    }
    interface Window {
        msCrypto?: any;
    }
}
export declare enum Format {
    Utf8 = "utf8",
    Base64 = "base64",
    Hex = "hex",
    Binary = "binary"
}
/**
 * Returns `window` if available, or `global` if supported in environment.
 */
export declare function getGlobalScope(): Window & typeof globalThis;
/**
 * Determines whether we are in an Internet Explorer or Edge environment
 * @access public
 */
export declare function ieOrEdge(): any;
/**
 * Returns true if WebCrypto is available
 * @access public
 */
export declare function isWebCryptoAvailable(): boolean;
/**
 * Returns the WebCrypto instance
 * @access public
 */
export declare function getSubtleCrypto(): SubtleCrypto | null;
/**
 * Generates a UUID syncronously
 * @access public
 */
export declare function generateUUIDSync(): string;
/**
 * Constant-time string comparison
 * @param a
 * @param b
 */
export declare function timingSafeEqual(a: string, b: string): boolean;
/**
 * Determines if the input value is a string
 */
export declare function isString(value: any): boolean;
/**
 * Converts a plain string into an ArrayBuffer
 * @param {string} string - A plain string
 */
export declare function stringToArrayBuffer(string: string): Promise<Uint8Array>;
/**
 * Converts an ArrayBuffer into a plain string
 * @param {ArrayBuffer} arrayBuffer
 */
export declare function arrayBufferToString(arrayBuffer: ArrayBuffer): Promise<string>;
/**
 * Converts an ArrayBuffer into a hex string
 * @param arrayBuffer
 */
export declare function arrayBufferToHexString(arrayBuffer: ArrayBuffer): Promise<string>;
/**
 * Converts a hex string into an ArrayBuffer
 * @access public
 * @param hex - A hex string
 */
export declare function hexStringToArrayBuffer(hex: string): Promise<Uint8Array>;
/**
 * Converts a base64 string into an ArrayBuffer
 * @param base64 - A base64 string
 */
export declare function base64ToArrayBuffer(base64: string): Promise<Uint8Array>;
/**
 * Converts an ArrayBuffer into a base64 string
 * @param buffer
 */
export declare function arrayBufferToBase64(arrayBuffer: ArrayBuffer): Promise<string>;
/**
 * Converts a hex string into a base64 string
 * @param hex - A hex string
 */
export declare function hexToBase64(hex: string): Promise<string>;
/**
 * Converts a base64 string into a hex string
 * @param base64 - A base64 string
 */
export declare function base64ToHex(base64: string): Promise<string>;
/**
 * Converts a plain string into base64
 * @param text - A plain string
 * @returns  A base64 encoded string
 */
export declare function base64Encode(text: string): Promise<string>;
/**
 * Converts a base64 string into a plain string
 * @param base64String - A base64 encoded string
 * @returns A plain string
 */
export declare function base64Decode(base64String: string): Promise<string>;
/**
 * Coerce input to a Buffer, throwing a TypeError if it cannot be coerced.
 * @param stringOrBuffer
 * @returns
 */
export declare function toBuffer(stringOrBuffer: string | ArrayBuffer, format: Format): Promise<Buffer>;
