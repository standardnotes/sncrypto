import { generateUUIDSync } from "@Lib/utils";

/**
 * Abstract class with default implementations of basic helper functions.
 */
export class SNPureCrypto {

  /** @access public */
  deinit() {
    /** Optional override */
  }

  /**
   * Generates a UUID string syncronously.
   * @returns {string}
   */
  generateUUIDSync() {
    return generateUUIDSync();
  }

  /**
   * Generates a UUID string asyncronously.
   * Can be overriden by native platforms to provide async implementation
   * @returns {Promise<string>}
   */
  async generateUUID() {
    return generateUUIDSync();
  }

  /**
   * Constant-time string comparison 
   * @param {string} a
   * @param {string} b
   * @returns {boolean} Whether the strings are equal
   */
  timingSafeEqual(a, b) {
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
}
