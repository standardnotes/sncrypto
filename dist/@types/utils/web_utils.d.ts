declare global {
    interface Document {
        documentMode?: any;
    }
    interface Window {
        msCrypto?: any;
    }
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
