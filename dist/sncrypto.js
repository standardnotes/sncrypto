!function(t,r){"object"==typeof exports&&"object"==typeof module?module.exports=r():"function"==typeof define&&define.amd?define("SNCrypto",[],r):"object"==typeof exports?exports.SNCrypto=r():t.SNCrypto=r()}(window,(function(){return function(t){function r(r){for(var e,o,i=r[0],u=r[1],a=0,f=[];a<i.length;a++)o=i[a],Object.prototype.hasOwnProperty.call(n,o)&&n[o]&&f.push(n[o][0]),n[o]=0;for(e in u)Object.prototype.hasOwnProperty.call(u,e)&&(t[e]=u[e]);for(s&&s(r);f.length;)f.shift()()}var e={},n={1:0,2:0};function o(r){if(e[r])return e[r].exports;var n=e[r]={i:r,l:!1,exports:{}};return t[r].call(n.exports,n,n.exports,o),n.l=!0,n.exports}o.e=function(t){var r=[],e=n[t];if(0!==e)if(e)r.push(e[2]);else{var i=new Promise((function(r,o){e=n[t]=[r,o]}));r.push(e[2]=i);var u,a=document.createElement("script");a.charset="utf-8",a.timeout=120,o.nc&&a.setAttribute("nonce",o.nc),a.src=function(t){return o.p+""+({0:"libsodium",3:"vendors~libsodium"}[t]||t)+".bundle.js"}(t);var s=new Error;u=function(r){a.onerror=a.onload=null,clearTimeout(f);var e=n[t];if(0!==e){if(e){var o=r&&("load"===r.type?"missing":r.type),i=r&&r.target&&r.target.src;s.message="Loading chunk "+t+" failed.\n("+o+": "+i+")",s.name="ChunkLoadError",s.type=o,s.request=i,e[1](s)}n[t]=void 0}};var f=setTimeout((function(){u({type:"timeout",target:a})}),12e4);a.onerror=a.onload=u,document.head.appendChild(a)}return Promise.all(r)},o.m=t,o.c=e,o.d=function(t,r,e){o.o(t,r)||Object.defineProperty(t,r,{enumerable:!0,get:e})},o.r=function(t){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(t,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(t,"__esModule",{value:!0})},o.t=function(t,r){if(1&r&&(t=o(t)),8&r)return t;if(4&r&&"object"==typeof t&&t&&t.__esModule)return t;var e=Object.create(null);if(o.r(e),Object.defineProperty(e,"default",{enumerable:!0,value:t}),2&r&&"string"!=typeof t)for(var n in t)o.d(e,n,function(r){return t[r]}.bind(null,n));return e},o.n=function(t){var r=t&&t.__esModule?function(){return t.default}:function(){return t};return o.d(r,"a",r),r},o.o=function(t,r){return Object.prototype.hasOwnProperty.call(t,r)},o.p="/dist/",o.oe=function(t){throw console.error(t),t};var i=window.webpackJsonpSNCrypto=window.webpackJsonpSNCrypto||[],u=i.push.bind(i);i.push=r,i=i.slice();for(var a=0;a<i.length;a++)r(i[a]);var s=u;return o(o.s=8)}([function(t,r,e){"use strict";(function(t){e.d(r,"a",(function(){return o})),e.d(r,"j",(function(){return i})),e.d(r,"o",(function(){return u})),e.d(r,"k",(function(){return a})),e.d(r,"i",(function(){return s})),e.d(r,"n",(function(){return f})),e.d(r,"p",(function(){return c})),e.d(r,"d",(function(){return h})),e.d(r,"c",(function(){return p})),e.d(r,"l",(function(){return l})),e.d(r,"g",(function(){return y})),e.d(r,"b",(function(){return g})),e.d(r,"m",(function(){return d})),e.d(r,"h",(function(){return w})),e.d(r,"f",(function(){return b})),e.d(r,"e",(function(){return v})),e.d(r,"q",(function(){return m}));var n=e(4),o=e(1).Buffer;function i(){return"undefined"!=typeof window?window:void 0!==t?t:null}function u(){return!("undefined"!=typeof document&&document.documentMode||/Edge/.test(navigator.userAgent))&&i().crypto&&!!i().crypto.subtle}function a(){return i().crypto?i().crypto.subtle:null}function s(){var t=i(),r=t.crypto||t.msCrypto;if(r){var e=new Uint32Array(4);r.getRandomValues(e);var n=-1;return"xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g,(function(t){n++;var r=e[n>>3]>>n%8*4&15;return("x"===t?r:3&r|8).toString(16)}))}var o=(new Date).getTime();return t.performance&&"function"==typeof t.performance.now&&(o+=performance.now()),"xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g,(function(t){var r=(o+16*Math.random())%16|0;return o=Math.floor(o/16),("x"===t?r:3&r|8).toString(16)}))}function f(t){return"string"==typeof t||t instanceof String}function c(t){return regeneratorRuntime.async((function(r){for(;;)switch(r.prev=r.next){case 0:return r.abrupt("return",new Promise((function(r,e){var n=new Blob([t]),o=new FileReader;o.onload=function(t){r(t.target.result)},o.readAsArrayBuffer(n)})));case 1:case"end":return r.stop()}}))}function h(t){return regeneratorRuntime.async((function(r){for(;;)switch(r.prev=r.next){case 0:return r.abrupt("return",new Promise((function(r,e){var n=new Blob([t]),o=new FileReader;o.onload=function(t){r(t.target.result)},o.readAsText(n)})));case 1:case"end":return r.stop()}}))}function p(t){var r,e,n,o;return regeneratorRuntime.async((function(i){for(;;)switch(i.prev=i.next){case 0:for(r=new Uint8Array(t),e="",o=0;o<r.byteLength;o++)(n=r[o].toString(16)).length<2&&(n="0"+n),e+=n;return i.abrupt("return",e);case 4:case"end":return i.stop()}}))}function l(t){var r,e;return regeneratorRuntime.async((function(n){for(;;)switch(n.prev=n.next){case 0:for(r=[],e=0;e<t.length;e+=2)r.push(parseInt(t.substr(e,2),16));return n.abrupt("return",new Uint8Array(r));case 3:case"end":return n.stop()}}))}function y(t){var r,e,n,o;return regeneratorRuntime.async((function(i){for(;;)switch(i.prev=i.next){case 0:return i.next=2,regeneratorRuntime.awrap(v(t));case 2:for(r=i.sent,e=r.length,n=new Uint8Array(e),o=0;o<e;o++)n[o]=r.charCodeAt(o);return i.abrupt("return",n.buffer);case 7:case"end":return i.stop()}}))}function g(t){return regeneratorRuntime.async((function(r){for(;;)switch(r.prev=r.next){case 0:return r.abrupt("return",new Promise((function(r,e){var n=new Blob([t],{type:"application/octet-binary"}),o=new FileReader;o.onload=function(t){var e=t.target.result;r(e.substr(e.indexOf(",")+1))},o.readAsDataURL(n)})));case 1:case"end":return r.stop()}}))}function d(t){var r;return regeneratorRuntime.async((function(e){for(;;)switch(e.prev=e.next){case 0:return r=o.from(t,"hex"),e.abrupt("return",r.toString("base64"));case 2:case"end":return e.stop()}}))}function w(t){var r;return regeneratorRuntime.async((function(e){for(;;)switch(e.prev=e.next){case 0:return r=o.from(t,"base64"),e.abrupt("return",r.toString("hex"));case 2:case"end":return e.stop()}}))}function b(t){return i().btoa(encodeURIComponent(t).replace(/%([0-9A-F]{2})/g,(function(t,r){return String.fromCharCode("0x"+r)})))}function v(t){return i().atob(t)}function m(t){var r,e=arguments;return regeneratorRuntime.async((function(i){for(;;)switch(i.prev=i.next){case 0:if(r=e.length>1&&void 0!==e[1]?e[1]:"binary",!o.isBuffer(t)){i.next=5;break}return i.abrupt("return",t);case 5:if(null!==t){i.next=9;break}return i.abrupt("return",null);case 9:if("string"!=typeof t){i.next=13;break}return i.abrupt("return",o.from(t,r));case 13:if(!(t instanceof Uint8Array)){i.next=17;break}return i.abrupt("return",n(t));case 17:if(!(t instanceof Promise)){i.next=21;break}return i.abrupt("return",t);case 21:throw new TypeError("Invalid type; string or buffer expected");case 22:case"end":return i.stop()}}))}}).call(this,e(2))},function(t,r,e){"use strict";(function(t){
/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <http://feross.org>
 * @license  MIT
 */
var n=e(5),o=e(6),i=e(3);function u(){return s.TYPED_ARRAY_SUPPORT?2147483647:1073741823}function a(t,r){if(u()<r)throw new RangeError("Invalid typed array length");return s.TYPED_ARRAY_SUPPORT?(t=new Uint8Array(r)).__proto__=s.prototype:(null===t&&(t=new s(r)),t.length=r),t}function s(t,r,e){if(!(s.TYPED_ARRAY_SUPPORT||this instanceof s))return new s(t,r,e);if("number"==typeof t){if("string"==typeof r)throw new Error("If encoding is specified then the first argument must be a string");return h(this,t)}return f(this,t,r,e)}function f(t,r,e,n){if("number"==typeof r)throw new TypeError('"value" argument must not be a number');return"undefined"!=typeof ArrayBuffer&&r instanceof ArrayBuffer?function(t,r,e,n){if(r.byteLength,e<0||r.byteLength<e)throw new RangeError("'offset' is out of bounds");if(r.byteLength<e+(n||0))throw new RangeError("'length' is out of bounds");r=void 0===e&&void 0===n?new Uint8Array(r):void 0===n?new Uint8Array(r,e):new Uint8Array(r,e,n);s.TYPED_ARRAY_SUPPORT?(t=r).__proto__=s.prototype:t=p(t,r);return t}(t,r,e,n):"string"==typeof r?function(t,r,e){"string"==typeof e&&""!==e||(e="utf8");if(!s.isEncoding(e))throw new TypeError('"encoding" must be a valid string encoding');var n=0|y(r,e),o=(t=a(t,n)).write(r,e);o!==n&&(t=t.slice(0,o));return t}(t,r,e):function(t,r){if(s.isBuffer(r)){var e=0|l(r.length);return 0===(t=a(t,e)).length?t:(r.copy(t,0,0,e),t)}if(r){if("undefined"!=typeof ArrayBuffer&&r.buffer instanceof ArrayBuffer||"length"in r)return"number"!=typeof r.length||(n=r.length)!=n?a(t,0):p(t,r);if("Buffer"===r.type&&i(r.data))return p(t,r.data)}var n;throw new TypeError("First argument must be a string, Buffer, ArrayBuffer, Array, or array-like object.")}(t,r)}function c(t){if("number"!=typeof t)throw new TypeError('"size" argument must be a number');if(t<0)throw new RangeError('"size" argument must not be negative')}function h(t,r){if(c(r),t=a(t,r<0?0:0|l(r)),!s.TYPED_ARRAY_SUPPORT)for(var e=0;e<r;++e)t[e]=0;return t}function p(t,r){var e=r.length<0?0:0|l(r.length);t=a(t,e);for(var n=0;n<e;n+=1)t[n]=255&r[n];return t}function l(t){if(t>=u())throw new RangeError("Attempt to allocate Buffer larger than maximum size: 0x"+u().toString(16)+" bytes");return 0|t}function y(t,r){if(s.isBuffer(t))return t.length;if("undefined"!=typeof ArrayBuffer&&"function"==typeof ArrayBuffer.isView&&(ArrayBuffer.isView(t)||t instanceof ArrayBuffer))return t.byteLength;"string"!=typeof t&&(t=""+t);var e=t.length;if(0===e)return 0;for(var n=!1;;)switch(r){case"ascii":case"latin1":case"binary":return e;case"utf8":case"utf-8":case void 0:return F(t).length;case"ucs2":case"ucs-2":case"utf16le":case"utf-16le":return 2*e;case"hex":return e>>>1;case"base64":return q(t).length;default:if(n)return F(t).length;r=(""+r).toLowerCase(),n=!0}}function g(t,r,e){var n=!1;if((void 0===r||r<0)&&(r=0),r>this.length)return"";if((void 0===e||e>this.length)&&(e=this.length),e<=0)return"";if((e>>>=0)<=(r>>>=0))return"";for(t||(t="utf8");;)switch(t){case"hex":return T(this,r,e);case"utf8":case"utf-8":return S(this,r,e);case"ascii":return B(this,r,e);case"latin1":case"binary":return U(this,r,e);case"base64":return _(this,r,e);case"ucs2":case"ucs-2":case"utf16le":case"utf-16le":return C(this,r,e);default:if(n)throw new TypeError("Unknown encoding: "+t);t=(t+"").toLowerCase(),n=!0}}function d(t,r,e){var n=t[r];t[r]=t[e],t[e]=n}function w(t,r,e,n,o){if(0===t.length)return-1;if("string"==typeof e?(n=e,e=0):e>2147483647?e=2147483647:e<-2147483648&&(e=-2147483648),e=+e,isNaN(e)&&(e=o?0:t.length-1),e<0&&(e=t.length+e),e>=t.length){if(o)return-1;e=t.length-1}else if(e<0){if(!o)return-1;e=0}if("string"==typeof r&&(r=s.from(r,n)),s.isBuffer(r))return 0===r.length?-1:b(t,r,e,n,o);if("number"==typeof r)return r&=255,s.TYPED_ARRAY_SUPPORT&&"function"==typeof Uint8Array.prototype.indexOf?o?Uint8Array.prototype.indexOf.call(t,r,e):Uint8Array.prototype.lastIndexOf.call(t,r,e):b(t,[r],e,n,o);throw new TypeError("val must be string, number or Buffer")}function b(t,r,e,n,o){var i,u=1,a=t.length,s=r.length;if(void 0!==n&&("ucs2"===(n=String(n).toLowerCase())||"ucs-2"===n||"utf16le"===n||"utf-16le"===n)){if(t.length<2||r.length<2)return-1;u=2,a/=2,s/=2,e/=2}function f(t,r){return 1===u?t[r]:t.readUInt16BE(r*u)}if(o){var c=-1;for(i=e;i<a;i++)if(f(t,i)===f(r,-1===c?0:i-c)){if(-1===c&&(c=i),i-c+1===s)return c*u}else-1!==c&&(i-=i-c),c=-1}else for(e+s>a&&(e=a-s),i=e;i>=0;i--){for(var h=!0,p=0;p<s;p++)if(f(t,i+p)!==f(r,p)){h=!1;break}if(h)return i}return-1}function v(t,r,e,n){e=Number(e)||0;var o=t.length-e;n?(n=Number(n))>o&&(n=o):n=o;var i=r.length;if(i%2!=0)throw new TypeError("Invalid hex string");n>i/2&&(n=i/2);for(var u=0;u<n;++u){var a=parseInt(r.substr(2*u,2),16);if(isNaN(a))return u;t[e+u]=a}return u}function m(t,r,e,n){return K(F(r,t.length-e),t,e,n)}function x(t,r,e,n){return K(function(t){for(var r=[],e=0;e<t.length;++e)r.push(255&t.charCodeAt(e));return r}(r),t,e,n)}function R(t,r,e,n){return x(t,r,e,n)}function A(t,r,e,n){return K(q(r),t,e,n)}function E(t,r,e,n){return K(function(t,r){for(var e,n,o,i=[],u=0;u<t.length&&!((r-=2)<0);++u)e=t.charCodeAt(u),n=e>>8,o=e%256,i.push(o),i.push(n);return i}(r,t.length-e),t,e,n)}function _(t,r,e){return 0===r&&e===t.length?n.fromByteArray(t):n.fromByteArray(t.slice(r,e))}function S(t,r,e){e=Math.min(t.length,e);for(var n=[],o=r;o<e;){var i,u,a,s,f=t[o],c=null,h=f>239?4:f>223?3:f>191?2:1;if(o+h<=e)switch(h){case 1:f<128&&(c=f);break;case 2:128==(192&(i=t[o+1]))&&(s=(31&f)<<6|63&i)>127&&(c=s);break;case 3:i=t[o+1],u=t[o+2],128==(192&i)&&128==(192&u)&&(s=(15&f)<<12|(63&i)<<6|63&u)>2047&&(s<55296||s>57343)&&(c=s);break;case 4:i=t[o+1],u=t[o+2],a=t[o+3],128==(192&i)&&128==(192&u)&&128==(192&a)&&(s=(15&f)<<18|(63&i)<<12|(63&u)<<6|63&a)>65535&&s<1114112&&(c=s)}null===c?(c=65533,h=1):c>65535&&(c-=65536,n.push(c>>>10&1023|55296),c=56320|1023&c),n.push(c),o+=h}return function(t){var r=t.length;if(r<=P)return String.fromCharCode.apply(String,t);var e="",n=0;for(;n<r;)e+=String.fromCharCode.apply(String,t.slice(n,n+=P));return e}(n)}r.Buffer=s,r.SlowBuffer=function(t){+t!=t&&(t=0);return s.alloc(+t)},r.INSPECT_MAX_BYTES=50,s.TYPED_ARRAY_SUPPORT=void 0!==t.TYPED_ARRAY_SUPPORT?t.TYPED_ARRAY_SUPPORT:function(){try{var t=new Uint8Array(1);return t.__proto__={__proto__:Uint8Array.prototype,foo:function(){return 42}},42===t.foo()&&"function"==typeof t.subarray&&0===t.subarray(1,1).byteLength}catch(t){return!1}}(),r.kMaxLength=u(),s.poolSize=8192,s._augment=function(t){return t.__proto__=s.prototype,t},s.from=function(t,r,e){return f(null,t,r,e)},s.TYPED_ARRAY_SUPPORT&&(s.prototype.__proto__=Uint8Array.prototype,s.__proto__=Uint8Array,"undefined"!=typeof Symbol&&Symbol.species&&s[Symbol.species]===s&&Object.defineProperty(s,Symbol.species,{value:null,configurable:!0})),s.alloc=function(t,r,e){return function(t,r,e,n){return c(r),r<=0?a(t,r):void 0!==e?"string"==typeof n?a(t,r).fill(e,n):a(t,r).fill(e):a(t,r)}(null,t,r,e)},s.allocUnsafe=function(t){return h(null,t)},s.allocUnsafeSlow=function(t){return h(null,t)},s.isBuffer=function(t){return!(null==t||!t._isBuffer)},s.compare=function(t,r){if(!s.isBuffer(t)||!s.isBuffer(r))throw new TypeError("Arguments must be Buffers");if(t===r)return 0;for(var e=t.length,n=r.length,o=0,i=Math.min(e,n);o<i;++o)if(t[o]!==r[o]){e=t[o],n=r[o];break}return e<n?-1:n<e?1:0},s.isEncoding=function(t){switch(String(t).toLowerCase()){case"hex":case"utf8":case"utf-8":case"ascii":case"latin1":case"binary":case"base64":case"ucs2":case"ucs-2":case"utf16le":case"utf-16le":return!0;default:return!1}},s.concat=function(t,r){if(!i(t))throw new TypeError('"list" argument must be an Array of Buffers');if(0===t.length)return s.alloc(0);var e;if(void 0===r)for(r=0,e=0;e<t.length;++e)r+=t[e].length;var n=s.allocUnsafe(r),o=0;for(e=0;e<t.length;++e){var u=t[e];if(!s.isBuffer(u))throw new TypeError('"list" argument must be an Array of Buffers');u.copy(n,o),o+=u.length}return n},s.byteLength=y,s.prototype._isBuffer=!0,s.prototype.swap16=function(){var t=this.length;if(t%2!=0)throw new RangeError("Buffer size must be a multiple of 16-bits");for(var r=0;r<t;r+=2)d(this,r,r+1);return this},s.prototype.swap32=function(){var t=this.length;if(t%4!=0)throw new RangeError("Buffer size must be a multiple of 32-bits");for(var r=0;r<t;r+=4)d(this,r,r+3),d(this,r+1,r+2);return this},s.prototype.swap64=function(){var t=this.length;if(t%8!=0)throw new RangeError("Buffer size must be a multiple of 64-bits");for(var r=0;r<t;r+=8)d(this,r,r+7),d(this,r+1,r+6),d(this,r+2,r+5),d(this,r+3,r+4);return this},s.prototype.toString=function(){var t=0|this.length;return 0===t?"":0===arguments.length?S(this,0,t):g.apply(this,arguments)},s.prototype.equals=function(t){if(!s.isBuffer(t))throw new TypeError("Argument must be a Buffer");return this===t||0===s.compare(this,t)},s.prototype.inspect=function(){var t="",e=r.INSPECT_MAX_BYTES;return this.length>0&&(t=this.toString("hex",0,e).match(/.{2}/g).join(" "),this.length>e&&(t+=" ... ")),"<Buffer "+t+">"},s.prototype.compare=function(t,r,e,n,o){if(!s.isBuffer(t))throw new TypeError("Argument must be a Buffer");if(void 0===r&&(r=0),void 0===e&&(e=t?t.length:0),void 0===n&&(n=0),void 0===o&&(o=this.length),r<0||e>t.length||n<0||o>this.length)throw new RangeError("out of range index");if(n>=o&&r>=e)return 0;if(n>=o)return-1;if(r>=e)return 1;if(this===t)return 0;for(var i=(o>>>=0)-(n>>>=0),u=(e>>>=0)-(r>>>=0),a=Math.min(i,u),f=this.slice(n,o),c=t.slice(r,e),h=0;h<a;++h)if(f[h]!==c[h]){i=f[h],u=c[h];break}return i<u?-1:u<i?1:0},s.prototype.includes=function(t,r,e){return-1!==this.indexOf(t,r,e)},s.prototype.indexOf=function(t,r,e){return w(this,t,r,e,!0)},s.prototype.lastIndexOf=function(t,r,e){return w(this,t,r,e,!1)},s.prototype.write=function(t,r,e,n){if(void 0===r)n="utf8",e=this.length,r=0;else if(void 0===e&&"string"==typeof r)n=r,e=this.length,r=0;else{if(!isFinite(r))throw new Error("Buffer.write(string, encoding, offset[, length]) is no longer supported");r|=0,isFinite(e)?(e|=0,void 0===n&&(n="utf8")):(n=e,e=void 0)}var o=this.length-r;if((void 0===e||e>o)&&(e=o),t.length>0&&(e<0||r<0)||r>this.length)throw new RangeError("Attempt to write outside buffer bounds");n||(n="utf8");for(var i=!1;;)switch(n){case"hex":return v(this,t,r,e);case"utf8":case"utf-8":return m(this,t,r,e);case"ascii":return x(this,t,r,e);case"latin1":case"binary":return R(this,t,r,e);case"base64":return A(this,t,r,e);case"ucs2":case"ucs-2":case"utf16le":case"utf-16le":return E(this,t,r,e);default:if(i)throw new TypeError("Unknown encoding: "+n);n=(""+n).toLowerCase(),i=!0}},s.prototype.toJSON=function(){return{type:"Buffer",data:Array.prototype.slice.call(this._arr||this,0)}};var P=4096;function B(t,r,e){var n="";e=Math.min(t.length,e);for(var o=r;o<e;++o)n+=String.fromCharCode(127&t[o]);return n}function U(t,r,e){var n="";e=Math.min(t.length,e);for(var o=r;o<e;++o)n+=String.fromCharCode(t[o]);return n}function T(t,r,e){var n=t.length;(!r||r<0)&&(r=0),(!e||e<0||e>n)&&(e=n);for(var o="",i=r;i<e;++i)o+=N(t[i]);return o}function C(t,r,e){for(var n=t.slice(r,e),o="",i=0;i<n.length;i+=2)o+=String.fromCharCode(n[i]+256*n[i+1]);return o}function O(t,r,e){if(t%1!=0||t<0)throw new RangeError("offset is not uint");if(t+r>e)throw new RangeError("Trying to access beyond buffer length")}function I(t,r,e,n,o,i){if(!s.isBuffer(t))throw new TypeError('"buffer" argument must be a Buffer instance');if(r>o||r<i)throw new RangeError('"value" argument is out of bounds');if(e+n>t.length)throw new RangeError("Index out of range")}function k(t,r,e,n){r<0&&(r=65535+r+1);for(var o=0,i=Math.min(t.length-e,2);o<i;++o)t[e+o]=(r&255<<8*(n?o:1-o))>>>8*(n?o:1-o)}function Y(t,r,e,n){r<0&&(r=4294967295+r+1);for(var o=0,i=Math.min(t.length-e,4);o<i;++o)t[e+o]=r>>>8*(n?o:3-o)&255}function j(t,r,e,n,o,i){if(e+n>t.length)throw new RangeError("Index out of range");if(e<0)throw new RangeError("Index out of range")}function L(t,r,e,n,i){return i||j(t,0,e,4),o.write(t,r,e,n,23,4),e+4}function M(t,r,e,n,i){return i||j(t,0,e,8),o.write(t,r,e,n,52,8),e+8}s.prototype.slice=function(t,r){var e,n=this.length;if((t=~~t)<0?(t+=n)<0&&(t=0):t>n&&(t=n),(r=void 0===r?n:~~r)<0?(r+=n)<0&&(r=0):r>n&&(r=n),r<t&&(r=t),s.TYPED_ARRAY_SUPPORT)(e=this.subarray(t,r)).__proto__=s.prototype;else{var o=r-t;e=new s(o,void 0);for(var i=0;i<o;++i)e[i]=this[i+t]}return e},s.prototype.readUIntLE=function(t,r,e){t|=0,r|=0,e||O(t,r,this.length);for(var n=this[t],o=1,i=0;++i<r&&(o*=256);)n+=this[t+i]*o;return n},s.prototype.readUIntBE=function(t,r,e){t|=0,r|=0,e||O(t,r,this.length);for(var n=this[t+--r],o=1;r>0&&(o*=256);)n+=this[t+--r]*o;return n},s.prototype.readUInt8=function(t,r){return r||O(t,1,this.length),this[t]},s.prototype.readUInt16LE=function(t,r){return r||O(t,2,this.length),this[t]|this[t+1]<<8},s.prototype.readUInt16BE=function(t,r){return r||O(t,2,this.length),this[t]<<8|this[t+1]},s.prototype.readUInt32LE=function(t,r){return r||O(t,4,this.length),(this[t]|this[t+1]<<8|this[t+2]<<16)+16777216*this[t+3]},s.prototype.readUInt32BE=function(t,r){return r||O(t,4,this.length),16777216*this[t]+(this[t+1]<<16|this[t+2]<<8|this[t+3])},s.prototype.readIntLE=function(t,r,e){t|=0,r|=0,e||O(t,r,this.length);for(var n=this[t],o=1,i=0;++i<r&&(o*=256);)n+=this[t+i]*o;return n>=(o*=128)&&(n-=Math.pow(2,8*r)),n},s.prototype.readIntBE=function(t,r,e){t|=0,r|=0,e||O(t,r,this.length);for(var n=r,o=1,i=this[t+--n];n>0&&(o*=256);)i+=this[t+--n]*o;return i>=(o*=128)&&(i-=Math.pow(2,8*r)),i},s.prototype.readInt8=function(t,r){return r||O(t,1,this.length),128&this[t]?-1*(255-this[t]+1):this[t]},s.prototype.readInt16LE=function(t,r){r||O(t,2,this.length);var e=this[t]|this[t+1]<<8;return 32768&e?4294901760|e:e},s.prototype.readInt16BE=function(t,r){r||O(t,2,this.length);var e=this[t+1]|this[t]<<8;return 32768&e?4294901760|e:e},s.prototype.readInt32LE=function(t,r){return r||O(t,4,this.length),this[t]|this[t+1]<<8|this[t+2]<<16|this[t+3]<<24},s.prototype.readInt32BE=function(t,r){return r||O(t,4,this.length),this[t]<<24|this[t+1]<<16|this[t+2]<<8|this[t+3]},s.prototype.readFloatLE=function(t,r){return r||O(t,4,this.length),o.read(this,t,!0,23,4)},s.prototype.readFloatBE=function(t,r){return r||O(t,4,this.length),o.read(this,t,!1,23,4)},s.prototype.readDoubleLE=function(t,r){return r||O(t,8,this.length),o.read(this,t,!0,52,8)},s.prototype.readDoubleBE=function(t,r){return r||O(t,8,this.length),o.read(this,t,!1,52,8)},s.prototype.writeUIntLE=function(t,r,e,n){(t=+t,r|=0,e|=0,n)||I(this,t,r,e,Math.pow(2,8*e)-1,0);var o=1,i=0;for(this[r]=255&t;++i<e&&(o*=256);)this[r+i]=t/o&255;return r+e},s.prototype.writeUIntBE=function(t,r,e,n){(t=+t,r|=0,e|=0,n)||I(this,t,r,e,Math.pow(2,8*e)-1,0);var o=e-1,i=1;for(this[r+o]=255&t;--o>=0&&(i*=256);)this[r+o]=t/i&255;return r+e},s.prototype.writeUInt8=function(t,r,e){return t=+t,r|=0,e||I(this,t,r,1,255,0),s.TYPED_ARRAY_SUPPORT||(t=Math.floor(t)),this[r]=255&t,r+1},s.prototype.writeUInt16LE=function(t,r,e){return t=+t,r|=0,e||I(this,t,r,2,65535,0),s.TYPED_ARRAY_SUPPORT?(this[r]=255&t,this[r+1]=t>>>8):k(this,t,r,!0),r+2},s.prototype.writeUInt16BE=function(t,r,e){return t=+t,r|=0,e||I(this,t,r,2,65535,0),s.TYPED_ARRAY_SUPPORT?(this[r]=t>>>8,this[r+1]=255&t):k(this,t,r,!1),r+2},s.prototype.writeUInt32LE=function(t,r,e){return t=+t,r|=0,e||I(this,t,r,4,4294967295,0),s.TYPED_ARRAY_SUPPORT?(this[r+3]=t>>>24,this[r+2]=t>>>16,this[r+1]=t>>>8,this[r]=255&t):Y(this,t,r,!0),r+4},s.prototype.writeUInt32BE=function(t,r,e){return t=+t,r|=0,e||I(this,t,r,4,4294967295,0),s.TYPED_ARRAY_SUPPORT?(this[r]=t>>>24,this[r+1]=t>>>16,this[r+2]=t>>>8,this[r+3]=255&t):Y(this,t,r,!1),r+4},s.prototype.writeIntLE=function(t,r,e,n){if(t=+t,r|=0,!n){var o=Math.pow(2,8*e-1);I(this,t,r,e,o-1,-o)}var i=0,u=1,a=0;for(this[r]=255&t;++i<e&&(u*=256);)t<0&&0===a&&0!==this[r+i-1]&&(a=1),this[r+i]=(t/u>>0)-a&255;return r+e},s.prototype.writeIntBE=function(t,r,e,n){if(t=+t,r|=0,!n){var o=Math.pow(2,8*e-1);I(this,t,r,e,o-1,-o)}var i=e-1,u=1,a=0;for(this[r+i]=255&t;--i>=0&&(u*=256);)t<0&&0===a&&0!==this[r+i+1]&&(a=1),this[r+i]=(t/u>>0)-a&255;return r+e},s.prototype.writeInt8=function(t,r,e){return t=+t,r|=0,e||I(this,t,r,1,127,-128),s.TYPED_ARRAY_SUPPORT||(t=Math.floor(t)),t<0&&(t=255+t+1),this[r]=255&t,r+1},s.prototype.writeInt16LE=function(t,r,e){return t=+t,r|=0,e||I(this,t,r,2,32767,-32768),s.TYPED_ARRAY_SUPPORT?(this[r]=255&t,this[r+1]=t>>>8):k(this,t,r,!0),r+2},s.prototype.writeInt16BE=function(t,r,e){return t=+t,r|=0,e||I(this,t,r,2,32767,-32768),s.TYPED_ARRAY_SUPPORT?(this[r]=t>>>8,this[r+1]=255&t):k(this,t,r,!1),r+2},s.prototype.writeInt32LE=function(t,r,e){return t=+t,r|=0,e||I(this,t,r,4,2147483647,-2147483648),s.TYPED_ARRAY_SUPPORT?(this[r]=255&t,this[r+1]=t>>>8,this[r+2]=t>>>16,this[r+3]=t>>>24):Y(this,t,r,!0),r+4},s.prototype.writeInt32BE=function(t,r,e){return t=+t,r|=0,e||I(this,t,r,4,2147483647,-2147483648),t<0&&(t=4294967295+t+1),s.TYPED_ARRAY_SUPPORT?(this[r]=t>>>24,this[r+1]=t>>>16,this[r+2]=t>>>8,this[r+3]=255&t):Y(this,t,r,!1),r+4},s.prototype.writeFloatLE=function(t,r,e){return L(this,t,r,!0,e)},s.prototype.writeFloatBE=function(t,r,e){return L(this,t,r,!1,e)},s.prototype.writeDoubleLE=function(t,r,e){return M(this,t,r,!0,e)},s.prototype.writeDoubleBE=function(t,r,e){return M(this,t,r,!1,e)},s.prototype.copy=function(t,r,e,n){if(e||(e=0),n||0===n||(n=this.length),r>=t.length&&(r=t.length),r||(r=0),n>0&&n<e&&(n=e),n===e)return 0;if(0===t.length||0===this.length)return 0;if(r<0)throw new RangeError("targetStart out of bounds");if(e<0||e>=this.length)throw new RangeError("sourceStart out of bounds");if(n<0)throw new RangeError("sourceEnd out of bounds");n>this.length&&(n=this.length),t.length-r<n-e&&(n=t.length-r+e);var o,i=n-e;if(this===t&&e<r&&r<n)for(o=i-1;o>=0;--o)t[o+r]=this[o+e];else if(i<1e3||!s.TYPED_ARRAY_SUPPORT)for(o=0;o<i;++o)t[o+r]=this[o+e];else Uint8Array.prototype.set.call(t,this.subarray(e,e+i),r);return i},s.prototype.fill=function(t,r,e,n){if("string"==typeof t){if("string"==typeof r?(n=r,r=0,e=this.length):"string"==typeof e&&(n=e,e=this.length),1===t.length){var o=t.charCodeAt(0);o<256&&(t=o)}if(void 0!==n&&"string"!=typeof n)throw new TypeError("encoding must be a string");if("string"==typeof n&&!s.isEncoding(n))throw new TypeError("Unknown encoding: "+n)}else"number"==typeof t&&(t&=255);if(r<0||this.length<r||this.length<e)throw new RangeError("Out of range index");if(e<=r)return this;var i;if(r>>>=0,e=void 0===e?this.length:e>>>0,t||(t=0),"number"==typeof t)for(i=r;i<e;++i)this[i]=t;else{var u=s.isBuffer(t)?t:F(new s(t,n).toString()),a=u.length;for(i=0;i<e-r;++i)this[i+r]=u[i%a]}return this};var D=/[^+\/0-9A-Za-z-_]/g;function N(t){return t<16?"0"+t.toString(16):t.toString(16)}function F(t,r){var e;r=r||1/0;for(var n=t.length,o=null,i=[],u=0;u<n;++u){if((e=t.charCodeAt(u))>55295&&e<57344){if(!o){if(e>56319){(r-=3)>-1&&i.push(239,191,189);continue}if(u+1===n){(r-=3)>-1&&i.push(239,191,189);continue}o=e;continue}if(e<56320){(r-=3)>-1&&i.push(239,191,189),o=e;continue}e=65536+(o-55296<<10|e-56320)}else o&&(r-=3)>-1&&i.push(239,191,189);if(o=null,e<128){if((r-=1)<0)break;i.push(e)}else if(e<2048){if((r-=2)<0)break;i.push(e>>6|192,63&e|128)}else if(e<65536){if((r-=3)<0)break;i.push(e>>12|224,e>>6&63|128,63&e|128)}else{if(!(e<1114112))throw new Error("Invalid code point");if((r-=4)<0)break;i.push(e>>18|240,e>>12&63|128,e>>6&63|128,63&e|128)}}return i}function q(t){return n.toByteArray(function(t){if((t=function(t){return t.trim?t.trim():t.replace(/^\s+|\s+$/g,"")}(t).replace(D,"")).length<2)return"";for(;t.length%4!=0;)t+="=";return t}(t))}function K(t,r,e,n){for(var o=0;o<n&&!(o+e>=r.length||o>=t.length);++o)r[o+e]=t[o];return o}}).call(this,e(2))},function(t,r){function e(t){return(e="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(t){return typeof t}:function(t){return t&&"function"==typeof Symbol&&t.constructor===Symbol&&t!==Symbol.prototype?"symbol":typeof t})(t)}var n;n=function(){return this}();try{n=n||new Function("return this")()}catch(t){"object"===("undefined"==typeof window?"undefined":e(window))&&(n=window)}t.exports=n},function(t,r){var e={}.toString;t.exports=Array.isArray||function(t){return"[object Array]"==e.call(t)}},function(t,r,e){(function(r){var n=e(7).strict;t.exports=function(t){if(n(t)){var e=r.from(t.buffer);return t.byteLength!==t.buffer.byteLength&&(e=e.slice(t.byteOffset,t.byteOffset+t.byteLength)),e}return r.from(t)}}).call(this,e(1).Buffer)},function(t,r,e){"use strict";r.byteLength=function(t){var r=f(t),e=r[0],n=r[1];return 3*(e+n)/4-n},r.toByteArray=function(t){var r,e,n=f(t),u=n[0],a=n[1],s=new i(function(t,r,e){return 3*(r+e)/4-e}(0,u,a)),c=0,h=a>0?u-4:u;for(e=0;e<h;e+=4)r=o[t.charCodeAt(e)]<<18|o[t.charCodeAt(e+1)]<<12|o[t.charCodeAt(e+2)]<<6|o[t.charCodeAt(e+3)],s[c++]=r>>16&255,s[c++]=r>>8&255,s[c++]=255&r;2===a&&(r=o[t.charCodeAt(e)]<<2|o[t.charCodeAt(e+1)]>>4,s[c++]=255&r);1===a&&(r=o[t.charCodeAt(e)]<<10|o[t.charCodeAt(e+1)]<<4|o[t.charCodeAt(e+2)]>>2,s[c++]=r>>8&255,s[c++]=255&r);return s},r.fromByteArray=function(t){for(var r,e=t.length,o=e%3,i=[],u=0,a=e-o;u<a;u+=16383)i.push(c(t,u,u+16383>a?a:u+16383));1===o?(r=t[e-1],i.push(n[r>>2]+n[r<<4&63]+"==")):2===o&&(r=(t[e-2]<<8)+t[e-1],i.push(n[r>>10]+n[r>>4&63]+n[r<<2&63]+"="));return i.join("")};for(var n=[],o=[],i="undefined"!=typeof Uint8Array?Uint8Array:Array,u="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",a=0,s=u.length;a<s;++a)n[a]=u[a],o[u.charCodeAt(a)]=a;function f(t){var r=t.length;if(r%4>0)throw new Error("Invalid string. Length must be a multiple of 4");var e=t.indexOf("=");return-1===e&&(e=r),[e,e===r?0:4-e%4]}function c(t,r,e){for(var o,i,u=[],a=r;a<e;a+=3)o=(t[a]<<16&16711680)+(t[a+1]<<8&65280)+(255&t[a+2]),u.push(n[(i=o)>>18&63]+n[i>>12&63]+n[i>>6&63]+n[63&i]);return u.join("")}o["-".charCodeAt(0)]=62,o["_".charCodeAt(0)]=63},function(t,r){r.read=function(t,r,e,n,o){var i,u,a=8*o-n-1,s=(1<<a)-1,f=s>>1,c=-7,h=e?o-1:0,p=e?-1:1,l=t[r+h];for(h+=p,i=l&(1<<-c)-1,l>>=-c,c+=a;c>0;i=256*i+t[r+h],h+=p,c-=8);for(u=i&(1<<-c)-1,i>>=-c,c+=n;c>0;u=256*u+t[r+h],h+=p,c-=8);if(0===i)i=1-f;else{if(i===s)return u?NaN:1/0*(l?-1:1);u+=Math.pow(2,n),i-=f}return(l?-1:1)*u*Math.pow(2,i-n)},r.write=function(t,r,e,n,o,i){var u,a,s,f=8*i-o-1,c=(1<<f)-1,h=c>>1,p=23===o?Math.pow(2,-24)-Math.pow(2,-77):0,l=n?0:i-1,y=n?1:-1,g=r<0||0===r&&1/r<0?1:0;for(r=Math.abs(r),isNaN(r)||r===1/0?(a=isNaN(r)?1:0,u=c):(u=Math.floor(Math.log(r)/Math.LN2),r*(s=Math.pow(2,-u))<1&&(u--,s*=2),(r+=u+h>=1?p/s:p*Math.pow(2,1-h))*s>=2&&(u++,s/=2),u+h>=c?(a=0,u=c):u+h>=1?(a=(r*s-1)*Math.pow(2,o),u+=h):(a=r*Math.pow(2,h-1)*Math.pow(2,o),u=0));o>=8;t[e+l]=255&a,l+=y,a/=256,o-=8);for(u=u<<o|a,f+=o;f>0;t[e+l]=255&u,l+=y,u/=256,f-=8);t[e+l-y]|=128*g}},function(t,r){t.exports=o,o.strict=i,o.loose=u;var e=Object.prototype.toString,n={"[object Int8Array]":!0,"[object Int16Array]":!0,"[object Int32Array]":!0,"[object Uint8Array]":!0,"[object Uint8ClampedArray]":!0,"[object Uint16Array]":!0,"[object Uint32Array]":!0,"[object Float32Array]":!0,"[object Float64Array]":!0};function o(t){return i(t)||u(t)}function i(t){return t instanceof Int8Array||t instanceof Int16Array||t instanceof Int32Array||t instanceof Uint8Array||t instanceof Uint8ClampedArray||t instanceof Uint16Array||t instanceof Uint32Array||t instanceof Float32Array||t instanceof Float64Array}function u(t){return n[e.call(t)]}},function(t,r,e){"use strict";e.r(r);var n=e(0);function o(t,r){for(var e=0;e<r.length;e++){var n=r[e];n.enumerable=n.enumerable||!1,n.configurable=!0,"value"in n&&(n.writable=!0),Object.defineProperty(t,n.key,n)}}var i=function(){function t(){!function(t,r){if(!(t instanceof r))throw new TypeError("Cannot call a class as a function")}(this,t)}var r,e,i;return r=t,(e=[{key:"generateUUIDSync",value:function(){return Object(n.i)()}},{key:"generateUUID",value:function(){return regeneratorRuntime.async((function(t){for(;;)switch(t.prev=t.next){case 0:return t.abrupt("return",Object(n.i)());case 1:case"end":return t.stop()}}))}},{key:"timingSafeEqual",value:function(t,r){var e=String(t),n=String(r),o=e.length,i=0;o!==n.length&&(n=e,i=1);for(var u=0;u<o;u++)i|=e.charCodeAt(u)^n.charCodeAt(u);return 0===i}}])&&o(r.prototype,e),i&&o(r,i),t}();function u(t){return(u="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(t){return typeof t}:function(t){return t&&"function"==typeof Symbol&&t.constructor===Symbol&&t!==Symbol.prototype?"symbol":typeof t})(t)}function a(t,r){for(var e=0;e<r.length;e++){var n=r[e];n.enumerable=n.enumerable||!1,n.configurable=!0,"value"in n&&(n.writable=!0),Object.defineProperty(t,n.key,n)}}function s(t,r){return!r||"object"!==u(r)&&"function"!=typeof r?function(t){if(void 0===t)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return t}(t):r}function f(t){return(f=Object.setPrototypeOf?Object.getPrototypeOf:function(t){return t.__proto__||Object.getPrototypeOf(t)})(t)}function c(t,r){return(c=Object.setPrototypeOf||function(t,r){return t.__proto__=r,t})(t,r)}var h=n.k(),p="AES-CBC",l="SHA-512",y="SHA-256",g="PBKDF2",d="SHA-1",w="HMAC",b="deriveBits",v="encrypt",m="decrypt",x="sign",R=function(t){function r(){var t;return function(t,r){if(!(t instanceof r))throw new TypeError("Cannot call a class as a function")}(this,r),(t=s(this,f(r).call(this))).ready=Promise.all([e.e(3),e.e(0)]).then(e.bind(null,166)).then((function(r){return t.sodium=r,t.sodium.ready})),t}var o,i,u;return function(t,r){if("function"!=typeof r&&null!==r)throw new TypeError("Super expression must either be null or a function");t.prototype=Object.create(r&&r.prototype,{constructor:{value:t,writable:!0,configurable:!0}}),r&&c(t,r)}(r,t),o=r,(i=[{key:"pbkdf2",value:function(t,r,e,n){var o;return regeneratorRuntime.async((function(i){for(;;)switch(i.prev=i.next){case 0:return i.next=2,regeneratorRuntime.awrap(this.webCryptoImportKey(t,g,[b]));case 2:if(o=i.sent){i.next=6;break}return console.error("Key is null, unable to continue"),i.abrupt("return",null);case 6:return i.abrupt("return",this.webCryptoDeriveBits(o,r,e,n));case 7:case"end":return i.stop()}}),null,this)}},{key:"generateRandomKey",value:function(t){var r,e;return regeneratorRuntime.async((function(o){for(;;)switch(o.prev=o.next){case 0:return r=t/8,e=n.j().crypto.getRandomValues(new Uint8Array(r)),o.abrupt("return",n.c(e));case 3:case"end":return o.stop()}}))}},{key:"aes256CbcEncrypt",value:function(t,r,e){var o,i,u,a,s,f,c;return regeneratorRuntime.async((function(h){for(;;)switch(h.prev=h.next){case 0:return h.next=2,regeneratorRuntime.awrap(n.l(e));case 2:return o=h.sent,h.next=5,regeneratorRuntime.awrap(n.l(r));case 5:return i=h.sent,u={name:p,iv:i},h.next=9,regeneratorRuntime.awrap(this.webCryptoImportKey(o,u.name,[v]));case 9:return a=h.sent,h.next=12,regeneratorRuntime.awrap(n.p(t));case 12:return s=h.sent,h.next=15,regeneratorRuntime.awrap(crypto.subtle.encrypt(u,a,s));case 15:return f=h.sent,h.next=18,regeneratorRuntime.awrap(n.b(f));case 18:return c=h.sent,h.abrupt("return",c);case 20:case"end":return h.stop()}}),null,this)}},{key:"aes256CbcDecrypt",value:function(t,r,e){var o,i,u,a,s;return regeneratorRuntime.async((function(f){for(;;)switch(f.prev=f.next){case 0:return f.next=2,regeneratorRuntime.awrap(n.l(e));case 2:return o=f.sent,f.next=5,regeneratorRuntime.awrap(n.l(r));case 5:return i=f.sent,u={name:p,iv:i},f.next=9,regeneratorRuntime.awrap(this.webCryptoImportKey(o,u.name,[m]));case 9:return a=f.sent,f.next=12,regeneratorRuntime.awrap(n.g(t));case 12:return s=f.sent,f.abrupt("return",crypto.subtle.decrypt(u,a,s).then((function(t){return regeneratorRuntime.async((function(r){for(;;)switch(r.prev=r.next){case 0:return r.abrupt("return",n.d(t));case 1:case"end":return r.stop()}}))})).catch((function(t){return console.error("Error performing AES-CBC decryption:",t),null})));case 14:case"end":return f.stop()}}),null,this)}},{key:"hmac256",value:function(t,r){var e,o,i;return regeneratorRuntime.async((function(u){for(;;)switch(u.prev=u.next){case 0:return u.next=2,regeneratorRuntime.awrap(n.l(r));case 2:return e=u.sent,u.next=5,regeneratorRuntime.awrap(this.webCryptoImportKey(e,w,[x],{name:y}));case 5:return o=u.sent,u.next=8,regeneratorRuntime.awrap(n.p(t));case 8:return i=u.sent,u.abrupt("return",crypto.subtle.sign({name:w},o,i).then((function(t){return n.c(t)})).catch((function(t){return console.error("Error computing HMAC:",t),null})));case 10:case"end":return u.stop()}}),null,this)}},{key:"sha256",value:function(t){var r,e;return regeneratorRuntime.async((function(o){for(;;)switch(o.prev=o.next){case 0:return o.next=2,regeneratorRuntime.awrap(n.p(t));case 2:return r=o.sent,o.next=5,regeneratorRuntime.awrap(crypto.subtle.digest(y,r));case 5:return e=o.sent,o.abrupt("return",n.c(e));case 7:case"end":return o.stop()}}))}},{key:"unsafeSha1",value:function(t){var r,e;return regeneratorRuntime.async((function(o){for(;;)switch(o.prev=o.next){case 0:return o.next=2,regeneratorRuntime.awrap(n.p(t));case 2:return r=o.sent,o.next=5,regeneratorRuntime.awrap(crypto.subtle.digest(d,r));case 5:return e=o.sent,o.abrupt("return",n.c(e));case 7:case"end":return o.stop()}}))}},{key:"webCryptoImportKey",value:function(t,r,e,o){var i;return regeneratorRuntime.async((function(u){for(;;)switch(u.prev=u.next){case 0:if(!n.n(t)){u.next=6;break}return u.next=3,regeneratorRuntime.awrap(n.p(t));case 3:u.t0=u.sent,u.next=7;break;case 6:u.t0=t;case 7:return i=u.t0,u.abrupt("return",h.importKey("raw",i,{name:r,hash:o},!1,e).then((function(t){return t})).catch((function(t){return console.error(t),null})));case 9:case"end":return u.stop()}}))}},{key:"webCryptoDeriveBits",value:function(t,r,e,o){var i;return regeneratorRuntime.async((function(u){for(;;)switch(u.prev=u.next){case 0:return u.t0=g,u.next=3,regeneratorRuntime.awrap(n.p(r));case 3:return u.t1=u.sent,u.t2=e,u.t3={name:l},i={name:u.t0,salt:u.t1,iterations:u.t2,hash:u.t3},u.abrupt("return",h.deriveBits(i,t,o).then((function(t){return n.c(new Uint8Array(t))})).catch((function(t){return console.error(t),null})));case 8:case"end":return u.stop()}}))}},{key:"argon2",value:function(t,r,e,o,i){var u;return regeneratorRuntime.async((function(a){for(;;)switch(a.prev=a.next){case 0:return a.next=2,regeneratorRuntime.awrap(this.ready);case 2:return a.t0=this.sodium,a.t1=i,a.next=6,regeneratorRuntime.awrap(n.q(t,"binary"));case 6:return a.t2=a.sent,a.next=9,regeneratorRuntime.awrap(n.q(r,"hex"));case 9:return a.t3=a.sent,a.t4=e,a.t5=o,a.t6=this.sodium.crypto_pwhash_ALG_DEFAULT,u=a.t0.crypto_pwhash.call(a.t0,a.t1,a.t2,a.t3,a.t4,a.t5,a.t6,"hex"),a.abrupt("return",u);case 15:case"end":return a.stop()}}),null,this)}},{key:"xchacha20Encrypt",value:function(t,r,e,o){return regeneratorRuntime.async((function(i){for(;;)switch(i.prev=i.next){case 0:return i.next=2,regeneratorRuntime.awrap(this.ready);case 2:if(48===r.length){i.next=4;break}throw"Nonce must be 24 bytes";case 4:return i.t0=this.sodium,i.next=7,regeneratorRuntime.awrap(n.q(t));case 7:return i.t1=i.sent,i.next=10,regeneratorRuntime.awrap(n.q(o));case 10:return i.t2=i.sent,i.next=13,regeneratorRuntime.awrap(n.q(r,"hex"));case 13:return i.t3=i.sent,i.next=16,regeneratorRuntime.awrap(n.q(e,"hex"));case 16:return i.t4=i.sent,i.abrupt("return",i.t0.crypto_aead_xchacha20poly1305_ietf_encrypt.call(i.t0,i.t1,i.t2,null,i.t3,i.t4,"base64"));case 18:case"end":return i.stop()}}),null,this)}},{key:"xchacha20Decrypt",value:function(t,r,e,o){return regeneratorRuntime.async((function(i){for(;;)switch(i.prev=i.next){case 0:return i.next=2,regeneratorRuntime.awrap(this.ready);case 2:if(48===r.length){i.next=4;break}throw"Nonce must be 24 bytes";case 4:return i.prev=4,i.t0=this.sodium,i.next=8,regeneratorRuntime.awrap(n.q(t,"base64"));case 8:return i.t1=i.sent,i.next=11,regeneratorRuntime.awrap(n.q(o));case 11:return i.t2=i.sent,i.next=14,regeneratorRuntime.awrap(n.q(r,"hex"));case 14:return i.t3=i.sent,i.next=17,regeneratorRuntime.awrap(n.q(e,"hex"));case 17:return i.t4=i.sent,i.abrupt("return",i.t0.crypto_aead_xchacha20poly1305_ietf_decrypt.call(i.t0,null,i.t1,i.t2,i.t3,i.t4,"text"));case 21:return i.prev=21,i.t5=i.catch(4),i.abrupt("return",null);case 24:case"end":return i.stop()}}),null,this,[[4,21]])}}])&&a(o.prototype,i),u&&a(o,u),r}(i);e.d(r,"SNPureCrypto",(function(){return i})),e.d(r,"SNWebCrypto",(function(){return R})),e.d(r,"isWebCryptoAvailable",(function(){return n.o})),e.d(r,"Buffer",(function(){return n.a})),e.d(r,"base64Encode",(function(){return n.f})),e.d(r,"base64Decode",(function(){return n.e})),e.d(r,"base64ToHex",(function(){return n.h})),e.d(r,"hexToBase64",(function(){return n.m}))}])}));
//# sourceMappingURL=sncrypto.js.map