/**
 *  Abstract class with default implementations of some crypto functions.
 */

import { getGlobalScope, generateUUIDSync } from "@Lib/utils";

export class SNPureCrypto {

  generateUUIDSync() {
    return generateUUIDSync();
  }

  /* Can be overriden by native platforms to provide async implementation; defaults here to syncronous */
  async generateUUID()  {
    return generateUUIDSync();
  }

  /* Constant-time string comparison */
  timingSafeEqual(a, b) {
    var strA = String(a);
    var strB = String(b);
    var lenA = strA.length;
    var result = 0;

    if(lenA !== strB.length) {
      strB = strA;
      result = 1;
    }

    for(var i = 0; i < lenA; i++) {
      result |= (strA.charCodeAt(i) ^ strB.charCodeAt(i));
    }

    return result === 0;
  }

  async base64(text) {
    return getGlobalScope().btoa(encodeURIComponent(text).replace(/%([0-9A-F]{2})/g,
      function toSolidBytes(match, p1) {
        return String.fromCharCode('0x' + p1);
    }));
  }

  async base64Decode(base64String) {
    return getGlobalScope().atob(base64String);
  }
}
