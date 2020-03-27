declare global {
  interface Document {
    documentMode?: any;
  }
  interface Window {
    msCrypto?: any
  }
}

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