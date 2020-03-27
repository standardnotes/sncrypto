import { generateUUIDSync } from "@Lib/utils";

/**
 * Abstract class with default implementations of basic helper functions.
 */
export class SNPureCrypto {

  public deinit() {
    /** Optional override */
  }

  /**
   * Generates a UUID string syncronously.
   */
  public generateUUIDSync() {
    return generateUUIDSync();
  }

  /**
   * Generates a UUID string asyncronously.
   * Can be overriden by native platforms to provide async implementation
   */
  public async generateUUID() {
    return generateUUIDSync();
  }

  /**
   * Constant-time string comparison 
   * @param {string} a
   * @param {string} b
   */
  public timingSafeEqual(a: string, b: string) {
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
