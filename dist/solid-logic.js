(function webpackUniversalModuleDefinition(root, factory) {
	if(typeof exports === 'object' && typeof module === 'object')
		module.exports = factory(require("$rdf"));
	else if(typeof define === 'function' && define.amd)
		define("SolidLogic", ["$rdf"], factory);
	else if(typeof exports === 'object')
		exports["SolidLogic"] = factory(require("$rdf"));
	else
		root["SolidLogic"] = factory(root["$rdf"]);
})(this, (__WEBPACK_EXTERNAL_MODULE__264__) => {
return /******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ 264
(module) {

"use strict";
module.exports = __WEBPACK_EXTERNAL_MODULE__264__;

/***/ },

/***/ 386
(module) {

/**
 * Provides a way to access commonly used namespaces
 *
 * Usage:
 *
 *   ```
 *   const $rdf = require('rdflib'); //or any other RDF/JS-compatible library
 *   const ns = require('solid-namespace')($rdf);
 *   const store = $rdf.graph();
 *
 *   let me = ...;
 *   let name = store.any(me, ns.vcard(‘fn’)) || store.any(me, ns.foaf(‘name’));
 *   ```
 * @module vocab
 */
const aliases = {
  acl: 'http://www.w3.org/ns/auth/acl#',
  arg: 'http://www.w3.org/ns/pim/arg#',
  as: 'https://www.w3.org/ns/activitystreams#',
  bookmark: 'http://www.w3.org/2002/01/bookmark#',
  cal: 'http://www.w3.org/2002/12/cal/ical#',
  cco: 'http://www.ontologyrepository.com/CommonCoreOntologies/',
  cert: 'http://www.w3.org/ns/auth/cert#',
  contact: 'http://www.w3.org/2000/10/swap/pim/contact#',
  dc: 'http://purl.org/dc/elements/1.1/',
  dct: 'http://purl.org/dc/terms/',
  doap: 'http://usefulinc.com/ns/doap#',
  foaf: 'http://xmlns.com/foaf/0.1/',
  geo: 'http://www.w3.org/2003/01/geo/wgs84_pos#',
  gpx: 'http://www.w3.org/ns/pim/gpx#',
  gr: 'http://purl.org/goodrelations/v1#',
  http: 'http://www.w3.org/2007/ont/http#',
  httph: 'http://www.w3.org/2007/ont/httph#',
  icalTZ: 'http://www.w3.org/2002/12/cal/icaltzd#', // Beware: not cal:
  ldp: 'http://www.w3.org/ns/ldp#',
  link: 'http://www.w3.org/2007/ont/link#',
  log: 'http://www.w3.org/2000/10/swap/log#',
  meeting: 'http://www.w3.org/ns/pim/meeting#',
  mo: 'http://purl.org/ontology/mo/',
  org: 'http://www.w3.org/ns/org#',
  owl: 'http://www.w3.org/2002/07/owl#',
  pad: 'http://www.w3.org/ns/pim/pad#',
  patch: 'http://www.w3.org/ns/pim/patch#',
  prov: 'http://www.w3.org/ns/prov#',
  pto: 'http://www.productontology.org/id/',
  qu: 'http://www.w3.org/2000/10/swap/pim/qif#',
  trip: 'http://www.w3.org/ns/pim/trip#',
  rdf: 'http://www.w3.org/1999/02/22-rdf-syntax-ns#',
  rdfs: 'http://www.w3.org/2000/01/rdf-schema#',
  rss: 'http://purl.org/rss/1.0/',
  sched: 'http://www.w3.org/ns/pim/schedule#',
  schema: 'http://schema.org/', // @@ beware confusion with documents no 303
  sioc: 'http://rdfs.org/sioc/ns#',
  skos: 'http://www.w3.org/2004/02/skos/core#',
  solid: 'http://www.w3.org/ns/solid/terms#',
  space: 'http://www.w3.org/ns/pim/space#',
  stat: 'http://www.w3.org/ns/posix/stat#',
  tab: 'http://www.w3.org/2007/ont/link#',
  tabont: 'http://www.w3.org/2007/ont/link#',
  ui: 'http://www.w3.org/ns/ui#',
  vann: 'http://purl.org/vocab/vann/',
  vcard: 'http://www.w3.org/2006/vcard/ns#',
  wf: 'http://www.w3.org/2005/01/wf/flow#',
  xsd: 'http://www.w3.org/2001/XMLSchema#',
}

/**
 * @param [rdflib] {RDF} Optional RDF Library (such as rdflib.js or rdf-ext) to inject
 */
function vocab (rdf = { namedNode: u => u }) {
  const namespaces = {}
  for (const alias in aliases) {
    const expansion = aliases[alias]
    namespaces[alias] = function (localName = '') {
      return rdf.namedNode(expansion + localName)
    }
  };

  return namespaces
};

module.exports = vocab


/***/ }

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId](module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/compat get default export */
/******/ 	(() => {
/******/ 		// getDefaultExport function for compatibility with non-harmony modules
/******/ 		__webpack_require__.n = (module) => {
/******/ 			var getter = module && module.__esModule ?
/******/ 				() => (module['default']) :
/******/ 				() => (module);
/******/ 			__webpack_require__.d(getter, { a: getter });
/******/ 			return getter;
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/define property getters */
/******/ 	(() => {
/******/ 		// define getter functions for harmony exports
/******/ 		__webpack_require__.d = (exports, definition) => {
/******/ 			for(var key in definition) {
/******/ 				if(__webpack_require__.o(definition, key) && !__webpack_require__.o(exports, key)) {
/******/ 					Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
/******/ 				}
/******/ 			}
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/global */
/******/ 	(() => {
/******/ 		__webpack_require__.g = (function() {
/******/ 			if (typeof globalThis === 'object') return globalThis;
/******/ 			try {
/******/ 				return this || new Function('return this')();
/******/ 			} catch (e) {
/******/ 				if (typeof window === 'object') return window;
/******/ 			}
/******/ 		})();
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/hasOwnProperty shorthand */
/******/ 	(() => {
/******/ 		__webpack_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop))
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/make namespace object */
/******/ 	(() => {
/******/ 		// define __esModule on exports
/******/ 		__webpack_require__.r = (exports) => {
/******/ 			if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 				Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 			}
/******/ 			Object.defineProperty(exports, '__esModule', { value: true });
/******/ 		};
/******/ 	})();
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry needs to be wrapped in an IIFE because it needs to be in strict mode.
(() => {
"use strict";
// ESM COMPAT FLAG
__webpack_require__.r(__webpack_exports__);

// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  ACL_LINK: () => (/* reexport */ ACL_LINK),
  CrossOriginForbiddenError: () => (/* reexport */ CrossOriginForbiddenError),
  FetchError: () => (/* reexport */ FetchError),
  NotEditableError: () => (/* reexport */ NotEditableError),
  NotFoundError: () => (/* reexport */ NotFoundError),
  SameOriginForbiddenError: () => (/* reexport */ SameOriginForbiddenError),
  UnauthorizedError: () => (/* reexport */ UnauthorizedError),
  WebOperationError: () => (/* reexport */ WebOperationError),
  appContext: () => (/* reexport */ appContext),
  authSession: () => (/* binding */ src_authSession),
  authn: () => (/* binding */ authn),
  createTypeIndexLogic: () => (/* reexport */ createTypeIndexLogic),
  getSuggestedIssuers: () => (/* reexport */ getSuggestedIssuers),
  offlineTestID: () => (/* reexport */ offlineTestID),
  solidLogicSingleton: () => (/* reexport */ solidLogicSingleton),
  store: () => (/* binding */ store)
});

;// ./src/util/debug.ts
function log(...args) {
    console.log(...args);
}
function warn(...args) {
    console.warn(...args);
}
function error(...args) {
    console.error(...args);
}
function trace(...args) {
    console.trace(...args);
}

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/runtime/webcrypto.js
/* harmony default export */ const webcrypto = (crypto);
const isCryptoKey = (key) => key instanceof CryptoKey;

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/lib/invalid_key_input.js
function message(msg, actual, ...types) {
    types = types.filter(Boolean);
    if (types.length > 2) {
        const last = types.pop();
        msg += `one of type ${types.join(', ')}, or ${last}.`;
    }
    else if (types.length === 2) {
        msg += `one of type ${types[0]} or ${types[1]}.`;
    }
    else {
        msg += `of type ${types[0]}.`;
    }
    if (actual == null) {
        msg += ` Received ${actual}`;
    }
    else if (typeof actual === 'function' && actual.name) {
        msg += ` Received function ${actual.name}`;
    }
    else if (typeof actual === 'object' && actual != null) {
        if (actual.constructor?.name) {
            msg += ` Received an instance of ${actual.constructor.name}`;
        }
    }
    return msg;
}
/* harmony default export */ const invalid_key_input = ((actual, ...types) => {
    return message('Key must be ', actual, ...types);
});
function withAlg(alg, actual, ...types) {
    return message(`Key for the ${alg} algorithm must be `, actual, ...types);
}

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/lib/buffer_utils.js

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const MAX_INT32 = (/* unused pure expression or super */ null && (2 ** 32));
function concat(...buffers) {
    const size = buffers.reduce((acc, { length }) => acc + length, 0);
    const buf = new Uint8Array(size);
    let i = 0;
    for (const buffer of buffers) {
        buf.set(buffer, i);
        i += buffer.length;
    }
    return buf;
}
function p2s(alg, p2sInput) {
    return concat(encoder.encode(alg), new Uint8Array([0]), p2sInput);
}
function writeUInt32BE(buf, value, offset) {
    if (value < 0 || value >= MAX_INT32) {
        throw new RangeError(`value must be >= 0 and <= ${MAX_INT32 - 1}. Received ${value}`);
    }
    buf.set([value >>> 24, value >>> 16, value >>> 8, value & 0xff], offset);
}
function uint64be(value) {
    const high = Math.floor(value / MAX_INT32);
    const low = value % MAX_INT32;
    const buf = new Uint8Array(8);
    writeUInt32BE(buf, high, 0);
    writeUInt32BE(buf, low, 4);
    return buf;
}
function uint32be(value) {
    const buf = new Uint8Array(4);
    writeUInt32BE(buf, value);
    return buf;
}
function lengthAndInput(input) {
    return concat(uint32be(input.length), input);
}
async function concatKdf(secret, bits, value) {
    const iterations = Math.ceil((bits >> 3) / 32);
    const res = new Uint8Array(iterations * 32);
    for (let iter = 0; iter < iterations; iter++) {
        const buf = new Uint8Array(4 + secret.length + value.length);
        buf.set(uint32be(iter + 1));
        buf.set(secret, 4);
        buf.set(value, 4 + secret.length);
        res.set(await digest('sha256', buf), iter * 32);
    }
    return res.slice(0, bits >> 3);
}

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/runtime/base64url.js

const encodeBase64 = (input) => {
    let unencoded = input;
    if (typeof unencoded === 'string') {
        unencoded = encoder.encode(unencoded);
    }
    const CHUNK_SIZE = 0x8000;
    const arr = [];
    for (let i = 0; i < unencoded.length; i += CHUNK_SIZE) {
        arr.push(String.fromCharCode.apply(null, unencoded.subarray(i, i + CHUNK_SIZE)));
    }
    return btoa(arr.join(''));
};
const encode = (input) => {
    return encodeBase64(input).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
};
const decodeBase64 = (encoded) => {
    const binary = atob(encoded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
};
const decode = (input) => {
    let encoded = input;
    if (encoded instanceof Uint8Array) {
        encoded = decoder.decode(encoded);
    }
    encoded = encoded.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
    try {
        return decodeBase64(encoded);
    }
    catch {
        throw new TypeError('The input to be decoded is not correctly encoded.');
    }
};

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/runtime/is_key_like.js

/* harmony default export */ const is_key_like = ((key) => {
    if (isCryptoKey(key)) {
        return true;
    }
    return key?.[Symbol.toStringTag] === 'KeyObject';
});
const types = ['CryptoKey'];

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/runtime/key_to_jwk.js




const keyToJWK = async (key) => {
    if (key instanceof Uint8Array) {
        return {
            kty: 'oct',
            k: encode(key),
        };
    }
    if (!isCryptoKey(key)) {
        throw new TypeError(invalid_key_input(key, ...types, 'Uint8Array'));
    }
    if (!key.extractable) {
        throw new TypeError('non-extractable CryptoKey cannot be exported as a JWK');
    }
    const { ext, key_ops, alg, use, ...jwk } = await webcrypto.subtle.exportKey('jwk', key);
    return jwk;
};
/* harmony default export */ const key_to_jwk = (keyToJWK);

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/key/export.js



async function exportSPKI(key) {
    return exportPublic(key);
}
async function exportPKCS8(key) {
    return exportPrivate(key);
}
async function exportJWK(key) {
    return key_to_jwk(key);
}

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/util/errors.js
class JOSEError extends Error {
    constructor(message, options) {
        super(message, options);
        this.code = 'ERR_JOSE_GENERIC';
        this.name = this.constructor.name;
        Error.captureStackTrace?.(this, this.constructor);
    }
}
JOSEError.code = 'ERR_JOSE_GENERIC';
class JWTClaimValidationFailed extends JOSEError {
    constructor(message, payload, claim = 'unspecified', reason = 'unspecified') {
        super(message, { cause: { claim, reason, payload } });
        this.code = 'ERR_JWT_CLAIM_VALIDATION_FAILED';
        this.claim = claim;
        this.reason = reason;
        this.payload = payload;
    }
}
JWTClaimValidationFailed.code = 'ERR_JWT_CLAIM_VALIDATION_FAILED';
class JWTExpired extends JOSEError {
    constructor(message, payload, claim = 'unspecified', reason = 'unspecified') {
        super(message, { cause: { claim, reason, payload } });
        this.code = 'ERR_JWT_EXPIRED';
        this.claim = claim;
        this.reason = reason;
        this.payload = payload;
    }
}
JWTExpired.code = 'ERR_JWT_EXPIRED';
class JOSEAlgNotAllowed extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JOSE_ALG_NOT_ALLOWED';
    }
}
JOSEAlgNotAllowed.code = 'ERR_JOSE_ALG_NOT_ALLOWED';
class errors_JOSENotSupported extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JOSE_NOT_SUPPORTED';
    }
}
errors_JOSENotSupported.code = 'ERR_JOSE_NOT_SUPPORTED';
class JWEDecryptionFailed extends JOSEError {
    constructor(message = 'decryption operation failed', options) {
        super(message, options);
        this.code = 'ERR_JWE_DECRYPTION_FAILED';
    }
}
JWEDecryptionFailed.code = 'ERR_JWE_DECRYPTION_FAILED';
class JWEInvalid extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JWE_INVALID';
    }
}
JWEInvalid.code = 'ERR_JWE_INVALID';
class JWSInvalid extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JWS_INVALID';
    }
}
JWSInvalid.code = 'ERR_JWS_INVALID';
class JWTInvalid extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JWT_INVALID';
    }
}
JWTInvalid.code = 'ERR_JWT_INVALID';
class JWKInvalid extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JWK_INVALID';
    }
}
JWKInvalid.code = 'ERR_JWK_INVALID';
class JWKSInvalid extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JWKS_INVALID';
    }
}
JWKSInvalid.code = 'ERR_JWKS_INVALID';
class JWKSNoMatchingKey extends JOSEError {
    constructor(message = 'no applicable key found in the JSON Web Key Set', options) {
        super(message, options);
        this.code = 'ERR_JWKS_NO_MATCHING_KEY';
    }
}
JWKSNoMatchingKey.code = 'ERR_JWKS_NO_MATCHING_KEY';
class JWKSMultipleMatchingKeys extends JOSEError {
    constructor(message = 'multiple matching keys found in the JSON Web Key Set', options) {
        super(message, options);
        this.code = 'ERR_JWKS_MULTIPLE_MATCHING_KEYS';
    }
}
Symbol.asyncIterator;
JWKSMultipleMatchingKeys.code = 'ERR_JWKS_MULTIPLE_MATCHING_KEYS';
class JWKSTimeout extends JOSEError {
    constructor(message = 'request timed out', options) {
        super(message, options);
        this.code = 'ERR_JWKS_TIMEOUT';
    }
}
JWKSTimeout.code = 'ERR_JWKS_TIMEOUT';
class JWSSignatureVerificationFailed extends JOSEError {
    constructor(message = 'signature verification failed', options) {
        super(message, options);
        this.code = 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED';
    }
}
JWSSignatureVerificationFailed.code = 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED';

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/runtime/subtle_dsa.js

function subtleDsa(alg, algorithm) {
    const hash = `SHA-${alg.slice(-3)}`;
    switch (alg) {
        case 'HS256':
        case 'HS384':
        case 'HS512':
            return { hash, name: 'HMAC' };
        case 'PS256':
        case 'PS384':
        case 'PS512':
            return { hash, name: 'RSA-PSS', saltLength: alg.slice(-3) >> 3 };
        case 'RS256':
        case 'RS384':
        case 'RS512':
            return { hash, name: 'RSASSA-PKCS1-v1_5' };
        case 'ES256':
        case 'ES384':
        case 'ES512':
            return { hash, name: 'ECDSA', namedCurve: algorithm.namedCurve };
        case 'Ed25519':
            return { name: 'Ed25519' };
        case 'EdDSA':
            return { name: algorithm.name };
        default:
            throw new errors_JOSENotSupported(`alg ${alg} is not supported either by JOSE or your javascript runtime`);
    }
}

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/runtime/check_key_length.js
/* harmony default export */ const check_key_length = ((alg, key) => {
    if (alg.startsWith('RS') || alg.startsWith('PS')) {
        const { modulusLength } = key.algorithm;
        if (typeof modulusLength !== 'number' || modulusLength < 2048) {
            throw new TypeError(`${alg} requires key modulusLength to be 2048 bits or larger`);
        }
    }
});

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/lib/crypto_key.js
function unusable(name, prop = 'algorithm.name') {
    return new TypeError(`CryptoKey does not support this operation, its ${prop} must be ${name}`);
}
function isAlgorithm(algorithm, name) {
    return algorithm.name === name;
}
function getHashLength(hash) {
    return parseInt(hash.name.slice(4), 10);
}
function getNamedCurve(alg) {
    switch (alg) {
        case 'ES256':
            return 'P-256';
        case 'ES384':
            return 'P-384';
        case 'ES512':
            return 'P-521';
        default:
            throw new Error('unreachable');
    }
}
function checkUsage(key, usages) {
    if (usages.length && !usages.some((expected) => key.usages.includes(expected))) {
        let msg = 'CryptoKey does not support this operation, its usages must include ';
        if (usages.length > 2) {
            const last = usages.pop();
            msg += `one of ${usages.join(', ')}, or ${last}.`;
        }
        else if (usages.length === 2) {
            msg += `one of ${usages[0]} or ${usages[1]}.`;
        }
        else {
            msg += `${usages[0]}.`;
        }
        throw new TypeError(msg);
    }
}
function checkSigCryptoKey(key, alg, ...usages) {
    switch (alg) {
        case 'HS256':
        case 'HS384':
        case 'HS512': {
            if (!isAlgorithm(key.algorithm, 'HMAC'))
                throw unusable('HMAC');
            const expected = parseInt(alg.slice(2), 10);
            const actual = getHashLength(key.algorithm.hash);
            if (actual !== expected)
                throw unusable(`SHA-${expected}`, 'algorithm.hash');
            break;
        }
        case 'RS256':
        case 'RS384':
        case 'RS512': {
            if (!isAlgorithm(key.algorithm, 'RSASSA-PKCS1-v1_5'))
                throw unusable('RSASSA-PKCS1-v1_5');
            const expected = parseInt(alg.slice(2), 10);
            const actual = getHashLength(key.algorithm.hash);
            if (actual !== expected)
                throw unusable(`SHA-${expected}`, 'algorithm.hash');
            break;
        }
        case 'PS256':
        case 'PS384':
        case 'PS512': {
            if (!isAlgorithm(key.algorithm, 'RSA-PSS'))
                throw unusable('RSA-PSS');
            const expected = parseInt(alg.slice(2), 10);
            const actual = getHashLength(key.algorithm.hash);
            if (actual !== expected)
                throw unusable(`SHA-${expected}`, 'algorithm.hash');
            break;
        }
        case 'EdDSA': {
            if (key.algorithm.name !== 'Ed25519' && key.algorithm.name !== 'Ed448') {
                throw unusable('Ed25519 or Ed448');
            }
            break;
        }
        case 'Ed25519': {
            if (!isAlgorithm(key.algorithm, 'Ed25519'))
                throw unusable('Ed25519');
            break;
        }
        case 'ES256':
        case 'ES384':
        case 'ES512': {
            if (!isAlgorithm(key.algorithm, 'ECDSA'))
                throw unusable('ECDSA');
            const expected = getNamedCurve(alg);
            const actual = key.algorithm.namedCurve;
            if (actual !== expected)
                throw unusable(expected, 'algorithm.namedCurve');
            break;
        }
        default:
            throw new TypeError('CryptoKey does not support this operation');
    }
    checkUsage(key, usages);
}
function checkEncCryptoKey(key, alg, ...usages) {
    switch (alg) {
        case 'A128GCM':
        case 'A192GCM':
        case 'A256GCM': {
            if (!isAlgorithm(key.algorithm, 'AES-GCM'))
                throw unusable('AES-GCM');
            const expected = parseInt(alg.slice(1, 4), 10);
            const actual = key.algorithm.length;
            if (actual !== expected)
                throw unusable(expected, 'algorithm.length');
            break;
        }
        case 'A128KW':
        case 'A192KW':
        case 'A256KW': {
            if (!isAlgorithm(key.algorithm, 'AES-KW'))
                throw unusable('AES-KW');
            const expected = parseInt(alg.slice(1, 4), 10);
            const actual = key.algorithm.length;
            if (actual !== expected)
                throw unusable(expected, 'algorithm.length');
            break;
        }
        case 'ECDH': {
            switch (key.algorithm.name) {
                case 'ECDH':
                case 'X25519':
                case 'X448':
                    break;
                default:
                    throw unusable('ECDH, X25519, or X448');
            }
            break;
        }
        case 'PBES2-HS256+A128KW':
        case 'PBES2-HS384+A192KW':
        case 'PBES2-HS512+A256KW':
            if (!isAlgorithm(key.algorithm, 'PBKDF2'))
                throw unusable('PBKDF2');
            break;
        case 'RSA-OAEP':
        case 'RSA-OAEP-256':
        case 'RSA-OAEP-384':
        case 'RSA-OAEP-512': {
            if (!isAlgorithm(key.algorithm, 'RSA-OAEP'))
                throw unusable('RSA-OAEP');
            const expected = parseInt(alg.slice(9), 10) || 1;
            const actual = getHashLength(key.algorithm.hash);
            if (actual !== expected)
                throw unusable(`SHA-${expected}`, 'algorithm.hash');
            break;
        }
        default:
            throw new TypeError('CryptoKey does not support this operation');
    }
    checkUsage(key, usages);
}

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/lib/is_object.js
function isObjectLike(value) {
    return typeof value === 'object' && value !== null;
}
function isObject(input) {
    if (!isObjectLike(input) || Object.prototype.toString.call(input) !== '[object Object]') {
        return false;
    }
    if (Object.getPrototypeOf(input) === null) {
        return true;
    }
    let proto = input;
    while (Object.getPrototypeOf(proto) !== null) {
        proto = Object.getPrototypeOf(proto);
    }
    return Object.getPrototypeOf(input) === proto;
}

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/lib/is_jwk.js

function isJWK(key) {
    return isObject(key) && typeof key.kty === 'string';
}
function isPrivateJWK(key) {
    return key.kty !== 'oct' && typeof key.d === 'string';
}
function isPublicJWK(key) {
    return key.kty !== 'oct' && typeof key.d === 'undefined';
}
function isSecretJWK(key) {
    return isJWK(key) && key.kty === 'oct' && typeof key.k === 'string';
}

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/runtime/jwk_to_key.js


function subtleMapping(jwk) {
    let algorithm;
    let keyUsages;
    switch (jwk.kty) {
        case 'RSA': {
            switch (jwk.alg) {
                case 'PS256':
                case 'PS384':
                case 'PS512':
                    algorithm = { name: 'RSA-PSS', hash: `SHA-${jwk.alg.slice(-3)}` };
                    keyUsages = jwk.d ? ['sign'] : ['verify'];
                    break;
                case 'RS256':
                case 'RS384':
                case 'RS512':
                    algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: `SHA-${jwk.alg.slice(-3)}` };
                    keyUsages = jwk.d ? ['sign'] : ['verify'];
                    break;
                case 'RSA-OAEP':
                case 'RSA-OAEP-256':
                case 'RSA-OAEP-384':
                case 'RSA-OAEP-512':
                    algorithm = {
                        name: 'RSA-OAEP',
                        hash: `SHA-${parseInt(jwk.alg.slice(-3), 10) || 1}`,
                    };
                    keyUsages = jwk.d ? ['decrypt', 'unwrapKey'] : ['encrypt', 'wrapKey'];
                    break;
                default:
                    throw new errors_JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
            }
            break;
        }
        case 'EC': {
            switch (jwk.alg) {
                case 'ES256':
                    algorithm = { name: 'ECDSA', namedCurve: 'P-256' };
                    keyUsages = jwk.d ? ['sign'] : ['verify'];
                    break;
                case 'ES384':
                    algorithm = { name: 'ECDSA', namedCurve: 'P-384' };
                    keyUsages = jwk.d ? ['sign'] : ['verify'];
                    break;
                case 'ES512':
                    algorithm = { name: 'ECDSA', namedCurve: 'P-521' };
                    keyUsages = jwk.d ? ['sign'] : ['verify'];
                    break;
                case 'ECDH-ES':
                case 'ECDH-ES+A128KW':
                case 'ECDH-ES+A192KW':
                case 'ECDH-ES+A256KW':
                    algorithm = { name: 'ECDH', namedCurve: jwk.crv };
                    keyUsages = jwk.d ? ['deriveBits'] : [];
                    break;
                default:
                    throw new errors_JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
            }
            break;
        }
        case 'OKP': {
            switch (jwk.alg) {
                case 'Ed25519':
                    algorithm = { name: 'Ed25519' };
                    keyUsages = jwk.d ? ['sign'] : ['verify'];
                    break;
                case 'EdDSA':
                    algorithm = { name: jwk.crv };
                    keyUsages = jwk.d ? ['sign'] : ['verify'];
                    break;
                case 'ECDH-ES':
                case 'ECDH-ES+A128KW':
                case 'ECDH-ES+A192KW':
                case 'ECDH-ES+A256KW':
                    algorithm = { name: jwk.crv };
                    keyUsages = jwk.d ? ['deriveBits'] : [];
                    break;
                default:
                    throw new errors_JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
            }
            break;
        }
        default:
            throw new errors_JOSENotSupported('Invalid or unsupported JWK "kty" (Key Type) Parameter value');
    }
    return { algorithm, keyUsages };
}
const parse = async (jwk) => {
    if (!jwk.alg) {
        throw new TypeError('"alg" argument is required when "jwk.alg" is not present');
    }
    const { algorithm, keyUsages } = subtleMapping(jwk);
    const rest = [
        algorithm,
        jwk.ext ?? false,
        jwk.key_ops ?? keyUsages,
    ];
    const keyData = { ...jwk };
    delete keyData.alg;
    delete keyData.use;
    return webcrypto.subtle.importKey('jwk', keyData, ...rest);
};
/* harmony default export */ const jwk_to_key = (parse);

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/runtime/normalize_key.js



const exportKeyValue = (k) => decode(k);
let privCache;
let pubCache;
const isKeyObject = (key) => {
    return key?.[Symbol.toStringTag] === 'KeyObject';
};
const importAndCache = async (cache, key, jwk, alg, freeze = false) => {
    let cached = cache.get(key);
    if (cached?.[alg]) {
        return cached[alg];
    }
    const cryptoKey = await jwk_to_key({ ...jwk, alg });
    if (freeze)
        Object.freeze(key);
    if (!cached) {
        cache.set(key, { [alg]: cryptoKey });
    }
    else {
        cached[alg] = cryptoKey;
    }
    return cryptoKey;
};
const normalizePublicKey = (key, alg) => {
    if (isKeyObject(key)) {
        let jwk = key.export({ format: 'jwk' });
        delete jwk.d;
        delete jwk.dp;
        delete jwk.dq;
        delete jwk.p;
        delete jwk.q;
        delete jwk.qi;
        if (jwk.k) {
            return exportKeyValue(jwk.k);
        }
        pubCache || (pubCache = new WeakMap());
        return importAndCache(pubCache, key, jwk, alg);
    }
    if (isJWK(key)) {
        if (key.k)
            return decode(key.k);
        pubCache || (pubCache = new WeakMap());
        const cryptoKey = importAndCache(pubCache, key, key, alg, true);
        return cryptoKey;
    }
    return key;
};
const normalizePrivateKey = (key, alg) => {
    if (isKeyObject(key)) {
        let jwk = key.export({ format: 'jwk' });
        if (jwk.k) {
            return exportKeyValue(jwk.k);
        }
        privCache || (privCache = new WeakMap());
        return importAndCache(privCache, key, jwk, alg);
    }
    if (isJWK(key)) {
        if (key.k)
            return decode(key.k);
        privCache || (privCache = new WeakMap());
        const cryptoKey = importAndCache(privCache, key, key, alg, true);
        return cryptoKey;
    }
    return key;
};
/* harmony default export */ const normalize_key = ({ normalizePublicKey, normalizePrivateKey });

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/runtime/get_sign_verify_key.js





async function getCryptoKey(alg, key, usage) {
    if (usage === 'sign') {
        key = await normalize_key.normalizePrivateKey(key, alg);
    }
    if (usage === 'verify') {
        key = await normalize_key.normalizePublicKey(key, alg);
    }
    if (isCryptoKey(key)) {
        checkSigCryptoKey(key, alg, usage);
        return key;
    }
    if (key instanceof Uint8Array) {
        if (!alg.startsWith('HS')) {
            throw new TypeError(invalid_key_input(key, ...types));
        }
        return webcrypto.subtle.importKey('raw', key, { hash: `SHA-${alg.slice(-3)}`, name: 'HMAC' }, false, [usage]);
    }
    throw new TypeError(invalid_key_input(key, ...types, 'Uint8Array', 'JSON Web Key'));
}

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/runtime/sign.js




const sign = async (alg, key, data) => {
    const cryptoKey = await getCryptoKey(alg, key, 'sign');
    check_key_length(alg, cryptoKey);
    const signature = await webcrypto.subtle.sign(subtleDsa(alg, cryptoKey.algorithm), cryptoKey, data);
    return new Uint8Array(signature);
};
/* harmony default export */ const runtime_sign = (sign);

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/lib/is_disjoint.js
const isDisjoint = (...headers) => {
    const sources = headers.filter(Boolean);
    if (sources.length === 0 || sources.length === 1) {
        return true;
    }
    let acc;
    for (const header of sources) {
        const parameters = Object.keys(header);
        if (!acc || acc.size === 0) {
            acc = new Set(parameters);
            continue;
        }
        for (const parameter of parameters) {
            if (acc.has(parameter)) {
                return false;
            }
            acc.add(parameter);
        }
    }
    return true;
};
/* harmony default export */ const is_disjoint = (isDisjoint);

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/lib/check_key_type.js



const tag = (key) => key?.[Symbol.toStringTag];
const jwkMatchesOp = (alg, key, usage) => {
    if (key.use !== undefined && key.use !== 'sig') {
        throw new TypeError('Invalid key for this operation, when present its use must be sig');
    }
    if (key.key_ops !== undefined && key.key_ops.includes?.(usage) !== true) {
        throw new TypeError(`Invalid key for this operation, when present its key_ops must include ${usage}`);
    }
    if (key.alg !== undefined && key.alg !== alg) {
        throw new TypeError(`Invalid key for this operation, when present its alg must be ${alg}`);
    }
    return true;
};
const symmetricTypeCheck = (alg, key, usage, allowJwk) => {
    if (key instanceof Uint8Array)
        return;
    if (allowJwk && isJWK(key)) {
        if (isSecretJWK(key) && jwkMatchesOp(alg, key, usage))
            return;
        throw new TypeError(`JSON Web Key for symmetric algorithms must have JWK "kty" (Key Type) equal to "oct" and the JWK "k" (Key Value) present`);
    }
    if (!is_key_like(key)) {
        throw new TypeError(withAlg(alg, key, ...types, 'Uint8Array', allowJwk ? 'JSON Web Key' : null));
    }
    if (key.type !== 'secret') {
        throw new TypeError(`${tag(key)} instances for symmetric algorithms must be of type "secret"`);
    }
};
const asymmetricTypeCheck = (alg, key, usage, allowJwk) => {
    if (allowJwk && isJWK(key)) {
        switch (usage) {
            case 'sign':
                if (isPrivateJWK(key) && jwkMatchesOp(alg, key, usage))
                    return;
                throw new TypeError(`JSON Web Key for this operation be a private JWK`);
            case 'verify':
                if (isPublicJWK(key) && jwkMatchesOp(alg, key, usage))
                    return;
                throw new TypeError(`JSON Web Key for this operation be a public JWK`);
        }
    }
    if (!is_key_like(key)) {
        throw new TypeError(withAlg(alg, key, ...types, allowJwk ? 'JSON Web Key' : null));
    }
    if (key.type === 'secret') {
        throw new TypeError(`${tag(key)} instances for asymmetric algorithms must not be of type "secret"`);
    }
    if (usage === 'sign' && key.type === 'public') {
        throw new TypeError(`${tag(key)} instances for asymmetric algorithm signing must be of type "private"`);
    }
    if (usage === 'decrypt' && key.type === 'public') {
        throw new TypeError(`${tag(key)} instances for asymmetric algorithm decryption must be of type "private"`);
    }
    if (key.algorithm && usage === 'verify' && key.type === 'private') {
        throw new TypeError(`${tag(key)} instances for asymmetric algorithm verifying must be of type "public"`);
    }
    if (key.algorithm && usage === 'encrypt' && key.type === 'private') {
        throw new TypeError(`${tag(key)} instances for asymmetric algorithm encryption must be of type "public"`);
    }
};
function checkKeyType(allowJwk, alg, key, usage) {
    const symmetric = alg.startsWith('HS') ||
        alg === 'dir' ||
        alg.startsWith('PBES2') ||
        /^A\d{3}(?:GCM)?KW$/.test(alg);
    if (symmetric) {
        symmetricTypeCheck(alg, key, usage, allowJwk);
    }
    else {
        asymmetricTypeCheck(alg, key, usage, allowJwk);
    }
}
/* harmony default export */ const check_key_type = (checkKeyType.bind(undefined, false));
const checkKeyTypeWithJwk = checkKeyType.bind(undefined, true);

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/lib/validate_crit.js

function validateCrit(Err, recognizedDefault, recognizedOption, protectedHeader, joseHeader) {
    if (joseHeader.crit !== undefined && protectedHeader?.crit === undefined) {
        throw new Err('"crit" (Critical) Header Parameter MUST be integrity protected');
    }
    if (!protectedHeader || protectedHeader.crit === undefined) {
        return new Set();
    }
    if (!Array.isArray(protectedHeader.crit) ||
        protectedHeader.crit.length === 0 ||
        protectedHeader.crit.some((input) => typeof input !== 'string' || input.length === 0)) {
        throw new Err('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present');
    }
    let recognized;
    if (recognizedOption !== undefined) {
        recognized = new Map([...Object.entries(recognizedOption), ...recognizedDefault.entries()]);
    }
    else {
        recognized = recognizedDefault;
    }
    for (const parameter of protectedHeader.crit) {
        if (!recognized.has(parameter)) {
            throw new errors_JOSENotSupported(`Extension Header Parameter "${parameter}" is not recognized`);
        }
        if (joseHeader[parameter] === undefined) {
            throw new Err(`Extension Header Parameter "${parameter}" is missing`);
        }
        if (recognized.get(parameter) && protectedHeader[parameter] === undefined) {
            throw new Err(`Extension Header Parameter "${parameter}" MUST be integrity protected`);
        }
    }
    return new Set(protectedHeader.crit);
}
/* harmony default export */ const validate_crit = (validateCrit);

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/jws/flattened/sign.js







class FlattenedSign {
    constructor(payload) {
        if (!(payload instanceof Uint8Array)) {
            throw new TypeError('payload must be an instance of Uint8Array');
        }
        this._payload = payload;
    }
    setProtectedHeader(protectedHeader) {
        if (this._protectedHeader) {
            throw new TypeError('setProtectedHeader can only be called once');
        }
        this._protectedHeader = protectedHeader;
        return this;
    }
    setUnprotectedHeader(unprotectedHeader) {
        if (this._unprotectedHeader) {
            throw new TypeError('setUnprotectedHeader can only be called once');
        }
        this._unprotectedHeader = unprotectedHeader;
        return this;
    }
    async sign(key, options) {
        if (!this._protectedHeader && !this._unprotectedHeader) {
            throw new JWSInvalid('either setProtectedHeader or setUnprotectedHeader must be called before #sign()');
        }
        if (!is_disjoint(this._protectedHeader, this._unprotectedHeader)) {
            throw new JWSInvalid('JWS Protected and JWS Unprotected Header Parameter names must be disjoint');
        }
        const joseHeader = {
            ...this._protectedHeader,
            ...this._unprotectedHeader,
        };
        const extensions = validate_crit(JWSInvalid, new Map([['b64', true]]), options?.crit, this._protectedHeader, joseHeader);
        let b64 = true;
        if (extensions.has('b64')) {
            b64 = this._protectedHeader.b64;
            if (typeof b64 !== 'boolean') {
                throw new JWSInvalid('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
            }
        }
        const { alg } = joseHeader;
        if (typeof alg !== 'string' || !alg) {
            throw new JWSInvalid('JWS "alg" (Algorithm) Header Parameter missing or invalid');
        }
        checkKeyTypeWithJwk(alg, key, 'sign');
        let payload = this._payload;
        if (b64) {
            payload = encoder.encode(encode(payload));
        }
        let protectedHeader;
        if (this._protectedHeader) {
            protectedHeader = encoder.encode(encode(JSON.stringify(this._protectedHeader)));
        }
        else {
            protectedHeader = encoder.encode('');
        }
        const data = concat(protectedHeader, encoder.encode('.'), payload);
        const signature = await runtime_sign(alg, key, data);
        const jws = {
            signature: encode(signature),
            payload: '',
        };
        if (b64) {
            jws.payload = decoder.decode(payload);
        }
        if (this._unprotectedHeader) {
            jws.header = this._unprotectedHeader;
        }
        if (this._protectedHeader) {
            jws.protected = decoder.decode(protectedHeader);
        }
        return jws;
    }
}

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/jws/compact/sign.js

class CompactSign {
    constructor(payload) {
        this._flattened = new FlattenedSign(payload);
    }
    setProtectedHeader(protectedHeader) {
        this._flattened.setProtectedHeader(protectedHeader);
        return this;
    }
    async sign(key, options) {
        const jws = await this._flattened.sign(key, options);
        if (jws.payload === undefined) {
            throw new TypeError('use the flattened module for creating JWS with b64: false');
        }
        return `${jws.protected}.${jws.payload}.${jws.signature}`;
    }
}

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/lib/epoch.js
/* harmony default export */ const epoch = ((date) => Math.floor(date.getTime() / 1000));

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/lib/secs.js
const minute = 60;
const hour = minute * 60;
const day = hour * 24;
const week = day * 7;
const year = day * 365.25;
const REGEX = /^(\+|\-)? ?(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?$/i;
/* harmony default export */ const secs = ((str) => {
    const matched = REGEX.exec(str);
    if (!matched || (matched[4] && matched[1])) {
        throw new TypeError('Invalid time period format');
    }
    const value = parseFloat(matched[2]);
    const unit = matched[3].toLowerCase();
    let numericDate;
    switch (unit) {
        case 'sec':
        case 'secs':
        case 'second':
        case 'seconds':
        case 's':
            numericDate = Math.round(value);
            break;
        case 'minute':
        case 'minutes':
        case 'min':
        case 'mins':
        case 'm':
            numericDate = Math.round(value * minute);
            break;
        case 'hour':
        case 'hours':
        case 'hr':
        case 'hrs':
        case 'h':
            numericDate = Math.round(value * hour);
            break;
        case 'day':
        case 'days':
        case 'd':
            numericDate = Math.round(value * day);
            break;
        case 'week':
        case 'weeks':
        case 'w':
            numericDate = Math.round(value * week);
            break;
        default:
            numericDate = Math.round(value * year);
            break;
    }
    if (matched[1] === '-' || matched[4] === 'ago') {
        return -numericDate;
    }
    return numericDate;
});

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/jwt/produce.js



function validateInput(label, input) {
    if (!Number.isFinite(input)) {
        throw new TypeError(`Invalid ${label} input`);
    }
    return input;
}
class ProduceJWT {
    constructor(payload = {}) {
        if (!isObject(payload)) {
            throw new TypeError('JWT Claims Set MUST be an object');
        }
        this._payload = payload;
    }
    setIssuer(issuer) {
        this._payload = { ...this._payload, iss: issuer };
        return this;
    }
    setSubject(subject) {
        this._payload = { ...this._payload, sub: subject };
        return this;
    }
    setAudience(audience) {
        this._payload = { ...this._payload, aud: audience };
        return this;
    }
    setJti(jwtId) {
        this._payload = { ...this._payload, jti: jwtId };
        return this;
    }
    setNotBefore(input) {
        if (typeof input === 'number') {
            this._payload = { ...this._payload, nbf: validateInput('setNotBefore', input) };
        }
        else if (input instanceof Date) {
            this._payload = { ...this._payload, nbf: validateInput('setNotBefore', epoch(input)) };
        }
        else {
            this._payload = { ...this._payload, nbf: epoch(new Date()) + secs(input) };
        }
        return this;
    }
    setExpirationTime(input) {
        if (typeof input === 'number') {
            this._payload = { ...this._payload, exp: validateInput('setExpirationTime', input) };
        }
        else if (input instanceof Date) {
            this._payload = { ...this._payload, exp: validateInput('setExpirationTime', epoch(input)) };
        }
        else {
            this._payload = { ...this._payload, exp: epoch(new Date()) + secs(input) };
        }
        return this;
    }
    setIssuedAt(input) {
        if (typeof input === 'undefined') {
            this._payload = { ...this._payload, iat: epoch(new Date()) };
        }
        else if (input instanceof Date) {
            this._payload = { ...this._payload, iat: validateInput('setIssuedAt', epoch(input)) };
        }
        else if (typeof input === 'string') {
            this._payload = {
                ...this._payload,
                iat: validateInput('setIssuedAt', epoch(new Date()) + secs(input)),
            };
        }
        else {
            this._payload = { ...this._payload, iat: validateInput('setIssuedAt', input) };
        }
        return this;
    }
}

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/jwt/sign.js




class SignJWT extends ProduceJWT {
    setProtectedHeader(protectedHeader) {
        this._protectedHeader = protectedHeader;
        return this;
    }
    async sign(key, options) {
        const sig = new CompactSign(encoder.encode(JSON.stringify(this._payload)));
        sig.setProtectedHeader(this._protectedHeader);
        if (Array.isArray(this._protectedHeader?.crit) &&
            this._protectedHeader.crit.includes('b64') &&
            this._protectedHeader.b64 === false) {
            throw new JWTInvalid('JWTs MUST NOT use unencoded payload');
        }
        return sig.sign(key, options);
    }
}

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/runtime/fetch_jwks.js

const fetchJwks = async (url, timeout, options) => {
    let controller;
    let id;
    let timedOut = false;
    if (typeof AbortController === 'function') {
        controller = new AbortController();
        id = setTimeout(() => {
            timedOut = true;
            controller.abort();
        }, timeout);
    }
    const response = await fetch(url.href, {
        signal: controller ? controller.signal : undefined,
        redirect: 'manual',
        headers: options.headers,
    }).catch((err) => {
        if (timedOut)
            throw new JWKSTimeout();
        throw err;
    });
    if (id !== undefined)
        clearTimeout(id);
    if (response.status !== 200) {
        throw new JOSEError('Expected 200 OK from the JSON Web Key Set HTTP response');
    }
    try {
        return await response.json();
    }
    catch {
        throw new JOSEError('Failed to parse the JSON Web Key Set HTTP response as JSON');
    }
};
/* harmony default export */ const fetch_jwks = (fetchJwks);

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/key/import.js





async function importSPKI(spki, alg, options) {
    if (typeof spki !== 'string' || spki.indexOf('-----BEGIN PUBLIC KEY-----') !== 0) {
        throw new TypeError('"spki" must be SPKI formatted string');
    }
    return fromSPKI(spki, alg, options);
}
async function importX509(x509, alg, options) {
    if (typeof x509 !== 'string' || x509.indexOf('-----BEGIN CERTIFICATE-----') !== 0) {
        throw new TypeError('"x509" must be X.509 formatted string');
    }
    return fromX509(x509, alg, options);
}
async function importPKCS8(pkcs8, alg, options) {
    if (typeof pkcs8 !== 'string' || pkcs8.indexOf('-----BEGIN PRIVATE KEY-----') !== 0) {
        throw new TypeError('"pkcs8" must be PKCS#8 formatted string');
    }
    return fromPKCS8(pkcs8, alg, options);
}
async function importJWK(jwk, alg) {
    if (!isObject(jwk)) {
        throw new TypeError('JWK must be an object');
    }
    alg || (alg = jwk.alg);
    switch (jwk.kty) {
        case 'oct':
            if (typeof jwk.k !== 'string' || !jwk.k) {
                throw new TypeError('missing "k" (Key Value) Parameter value');
            }
            return decode(jwk.k);
        case 'RSA':
            if ('oth' in jwk && jwk.oth !== undefined) {
                throw new errors_JOSENotSupported('RSA JWK "oth" (Other Primes Info) Parameter value is not supported');
            }
        case 'EC':
        case 'OKP':
            return jwk_to_key({ ...jwk, alg });
        default:
            throw new errors_JOSENotSupported('Unsupported "kty" (Key Type) Parameter value');
    }
}

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/jwks/local.js



function getKtyFromAlg(alg) {
    switch (typeof alg === 'string' && alg.slice(0, 2)) {
        case 'RS':
        case 'PS':
            return 'RSA';
        case 'ES':
            return 'EC';
        case 'Ed':
            return 'OKP';
        default:
            throw new errors_JOSENotSupported('Unsupported "alg" value for a JSON Web Key Set');
    }
}
function isJWKSLike(jwks) {
    return (jwks &&
        typeof jwks === 'object' &&
        Array.isArray(jwks.keys) &&
        jwks.keys.every(isJWKLike));
}
function isJWKLike(key) {
    return isObject(key);
}
function clone(obj) {
    if (typeof structuredClone === 'function') {
        return structuredClone(obj);
    }
    return JSON.parse(JSON.stringify(obj));
}
class LocalJWKSet {
    constructor(jwks) {
        this._cached = new WeakMap();
        if (!isJWKSLike(jwks)) {
            throw new JWKSInvalid('JSON Web Key Set malformed');
        }
        this._jwks = clone(jwks);
    }
    async getKey(protectedHeader, token) {
        const { alg, kid } = { ...protectedHeader, ...token?.header };
        const kty = getKtyFromAlg(alg);
        const candidates = this._jwks.keys.filter((jwk) => {
            let candidate = kty === jwk.kty;
            if (candidate && typeof kid === 'string') {
                candidate = kid === jwk.kid;
            }
            if (candidate && typeof jwk.alg === 'string') {
                candidate = alg === jwk.alg;
            }
            if (candidate && typeof jwk.use === 'string') {
                candidate = jwk.use === 'sig';
            }
            if (candidate && Array.isArray(jwk.key_ops)) {
                candidate = jwk.key_ops.includes('verify');
            }
            if (candidate) {
                switch (alg) {
                    case 'ES256':
                        candidate = jwk.crv === 'P-256';
                        break;
                    case 'ES256K':
                        candidate = jwk.crv === 'secp256k1';
                        break;
                    case 'ES384':
                        candidate = jwk.crv === 'P-384';
                        break;
                    case 'ES512':
                        candidate = jwk.crv === 'P-521';
                        break;
                    case 'Ed25519':
                        candidate = jwk.crv === 'Ed25519';
                        break;
                    case 'EdDSA':
                        candidate = jwk.crv === 'Ed25519' || jwk.crv === 'Ed448';
                        break;
                }
            }
            return candidate;
        });
        const { 0: jwk, length } = candidates;
        if (length === 0) {
            throw new JWKSNoMatchingKey();
        }
        if (length !== 1) {
            const error = new JWKSMultipleMatchingKeys();
            const { _cached } = this;
            error[Symbol.asyncIterator] = async function* () {
                for (const jwk of candidates) {
                    try {
                        yield await importWithAlgCache(_cached, jwk, alg);
                    }
                    catch { }
                }
            };
            throw error;
        }
        return importWithAlgCache(this._cached, jwk, alg);
    }
}
async function importWithAlgCache(cache, jwk, alg) {
    const cached = cache.get(jwk) || cache.set(jwk, {}).get(jwk);
    if (cached[alg] === undefined) {
        const key = await importJWK({ ...jwk, ext: true }, alg);
        if (key instanceof Uint8Array || key.type !== 'public') {
            throw new JWKSInvalid('JSON Web Key Set members must be public keys');
        }
        cached[alg] = key;
    }
    return cached[alg];
}
function createLocalJWKSet(jwks) {
    const set = new LocalJWKSet(jwks);
    const localJWKSet = async (protectedHeader, token) => set.getKey(protectedHeader, token);
    Object.defineProperties(localJWKSet, {
        jwks: {
            value: () => clone(set._jwks),
            enumerable: true,
            configurable: false,
            writable: false,
        },
    });
    return localJWKSet;
}

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/jwks/remote.js




function isCloudflareWorkers() {
    return (typeof WebSocketPair !== 'undefined' ||
        (typeof navigator !== 'undefined' && navigator.userAgent === 'Cloudflare-Workers') ||
        (typeof EdgeRuntime !== 'undefined' && EdgeRuntime === 'vercel'));
}
let USER_AGENT;
if (typeof navigator === 'undefined' || !navigator.userAgent?.startsWith?.('Mozilla/5.0 ')) {
    const NAME = 'jose';
    const VERSION = 'v5.10.0';
    USER_AGENT = `${NAME}/${VERSION}`;
}
const jwksCache = Symbol();
function isFreshJwksCache(input, cacheMaxAge) {
    if (typeof input !== 'object' || input === null) {
        return false;
    }
    if (!('uat' in input) || typeof input.uat !== 'number' || Date.now() - input.uat >= cacheMaxAge) {
        return false;
    }
    if (!('jwks' in input) ||
        !isObject(input.jwks) ||
        !Array.isArray(input.jwks.keys) ||
        !Array.prototype.every.call(input.jwks.keys, isObject)) {
        return false;
    }
    return true;
}
class RemoteJWKSet {
    constructor(url, options) {
        if (!(url instanceof URL)) {
            throw new TypeError('url must be an instance of URL');
        }
        this._url = new URL(url.href);
        this._options = { agent: options?.agent, headers: options?.headers };
        this._timeoutDuration =
            typeof options?.timeoutDuration === 'number' ? options?.timeoutDuration : 5000;
        this._cooldownDuration =
            typeof options?.cooldownDuration === 'number' ? options?.cooldownDuration : 30000;
        this._cacheMaxAge = typeof options?.cacheMaxAge === 'number' ? options?.cacheMaxAge : 600000;
        if (options?.[jwksCache] !== undefined) {
            this._cache = options?.[jwksCache];
            if (isFreshJwksCache(options?.[jwksCache], this._cacheMaxAge)) {
                this._jwksTimestamp = this._cache.uat;
                this._local = createLocalJWKSet(this._cache.jwks);
            }
        }
    }
    coolingDown() {
        return typeof this._jwksTimestamp === 'number'
            ? Date.now() < this._jwksTimestamp + this._cooldownDuration
            : false;
    }
    fresh() {
        return typeof this._jwksTimestamp === 'number'
            ? Date.now() < this._jwksTimestamp + this._cacheMaxAge
            : false;
    }
    async getKey(protectedHeader, token) {
        if (!this._local || !this.fresh()) {
            await this.reload();
        }
        try {
            return await this._local(protectedHeader, token);
        }
        catch (err) {
            if (err instanceof JWKSNoMatchingKey) {
                if (this.coolingDown() === false) {
                    await this.reload();
                    return this._local(protectedHeader, token);
                }
            }
            throw err;
        }
    }
    async reload() {
        if (this._pendingFetch && isCloudflareWorkers()) {
            this._pendingFetch = undefined;
        }
        const headers = new Headers(this._options.headers);
        if (USER_AGENT && !headers.has('User-Agent')) {
            headers.set('User-Agent', USER_AGENT);
            this._options.headers = Object.fromEntries(headers.entries());
        }
        this._pendingFetch || (this._pendingFetch = fetch_jwks(this._url, this._timeoutDuration, this._options)
            .then((json) => {
            this._local = createLocalJWKSet(json);
            if (this._cache) {
                this._cache.uat = Date.now();
                this._cache.jwks = json;
            }
            this._jwksTimestamp = Date.now();
            this._pendingFetch = undefined;
        })
            .catch((err) => {
            this._pendingFetch = undefined;
            throw err;
        }));
        await this._pendingFetch;
    }
}
function createRemoteJWKSet(url, options) {
    const set = new RemoteJWKSet(url, options);
    const remoteJWKSet = async (protectedHeader, token) => set.getKey(protectedHeader, token);
    Object.defineProperties(remoteJWKSet, {
        coolingDown: {
            get: () => set.coolingDown(),
            enumerable: true,
            configurable: false,
        },
        fresh: {
            get: () => set.fresh(),
            enumerable: true,
            configurable: false,
        },
        reload: {
            value: () => set.reload(),
            enumerable: true,
            configurable: false,
            writable: false,
        },
        reloading: {
            get: () => !!set._pendingFetch,
            enumerable: true,
            configurable: false,
        },
        jwks: {
            value: () => set._local?.jwks(),
            enumerable: true,
            configurable: false,
            writable: false,
        },
    });
    return remoteJWKSet;
}
const experimental_jwksCache = (/* unused pure expression or super */ null && (jwksCache));

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/runtime/verify.js




const verify = async (alg, key, signature, data) => {
    const cryptoKey = await getCryptoKey(alg, key, 'verify');
    check_key_length(alg, cryptoKey);
    const algorithm = subtleDsa(alg, cryptoKey.algorithm);
    try {
        return await webcrypto.subtle.verify(algorithm, cryptoKey, signature, data);
    }
    catch {
        return false;
    }
};
/* harmony default export */ const runtime_verify = (verify);

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/lib/validate_algorithms.js
const validateAlgorithms = (option, algorithms) => {
    if (algorithms !== undefined &&
        (!Array.isArray(algorithms) || algorithms.some((s) => typeof s !== 'string'))) {
        throw new TypeError(`"${option}" option must be an array of strings`);
    }
    if (!algorithms) {
        return undefined;
    }
    return new Set(algorithms);
};
/* harmony default export */ const validate_algorithms = (validateAlgorithms);

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/jws/flattened/verify.js











async function flattenedVerify(jws, key, options) {
    if (!isObject(jws)) {
        throw new JWSInvalid('Flattened JWS must be an object');
    }
    if (jws.protected === undefined && jws.header === undefined) {
        throw new JWSInvalid('Flattened JWS must have either of the "protected" or "header" members');
    }
    if (jws.protected !== undefined && typeof jws.protected !== 'string') {
        throw new JWSInvalid('JWS Protected Header incorrect type');
    }
    if (jws.payload === undefined) {
        throw new JWSInvalid('JWS Payload missing');
    }
    if (typeof jws.signature !== 'string') {
        throw new JWSInvalid('JWS Signature missing or incorrect type');
    }
    if (jws.header !== undefined && !isObject(jws.header)) {
        throw new JWSInvalid('JWS Unprotected Header incorrect type');
    }
    let parsedProt = {};
    if (jws.protected) {
        try {
            const protectedHeader = decode(jws.protected);
            parsedProt = JSON.parse(decoder.decode(protectedHeader));
        }
        catch {
            throw new JWSInvalid('JWS Protected Header is invalid');
        }
    }
    if (!is_disjoint(parsedProt, jws.header)) {
        throw new JWSInvalid('JWS Protected and JWS Unprotected Header Parameter names must be disjoint');
    }
    const joseHeader = {
        ...parsedProt,
        ...jws.header,
    };
    const extensions = validate_crit(JWSInvalid, new Map([['b64', true]]), options?.crit, parsedProt, joseHeader);
    let b64 = true;
    if (extensions.has('b64')) {
        b64 = parsedProt.b64;
        if (typeof b64 !== 'boolean') {
            throw new JWSInvalid('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
        }
    }
    const { alg } = joseHeader;
    if (typeof alg !== 'string' || !alg) {
        throw new JWSInvalid('JWS "alg" (Algorithm) Header Parameter missing or invalid');
    }
    const algorithms = options && validate_algorithms('algorithms', options.algorithms);
    if (algorithms && !algorithms.has(alg)) {
        throw new JOSEAlgNotAllowed('"alg" (Algorithm) Header Parameter value not allowed');
    }
    if (b64) {
        if (typeof jws.payload !== 'string') {
            throw new JWSInvalid('JWS Payload must be a string');
        }
    }
    else if (typeof jws.payload !== 'string' && !(jws.payload instanceof Uint8Array)) {
        throw new JWSInvalid('JWS Payload must be a string or an Uint8Array instance');
    }
    let resolvedKey = false;
    if (typeof key === 'function') {
        key = await key(parsedProt, jws);
        resolvedKey = true;
        checkKeyTypeWithJwk(alg, key, 'verify');
        if (isJWK(key)) {
            key = await importJWK(key, alg);
        }
    }
    else {
        checkKeyTypeWithJwk(alg, key, 'verify');
    }
    const data = concat(encoder.encode(jws.protected ?? ''), encoder.encode('.'), typeof jws.payload === 'string' ? encoder.encode(jws.payload) : jws.payload);
    let signature;
    try {
        signature = decode(jws.signature);
    }
    catch {
        throw new JWSInvalid('Failed to base64url decode the signature');
    }
    const verified = await runtime_verify(alg, key, signature, data);
    if (!verified) {
        throw new JWSSignatureVerificationFailed();
    }
    let payload;
    if (b64) {
        try {
            payload = decode(jws.payload);
        }
        catch {
            throw new JWSInvalid('Failed to base64url decode the payload');
        }
    }
    else if (typeof jws.payload === 'string') {
        payload = encoder.encode(jws.payload);
    }
    else {
        payload = jws.payload;
    }
    const result = { payload };
    if (jws.protected !== undefined) {
        result.protectedHeader = parsedProt;
    }
    if (jws.header !== undefined) {
        result.unprotectedHeader = jws.header;
    }
    if (resolvedKey) {
        return { ...result, key };
    }
    return result;
}

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/jws/compact/verify.js



async function compactVerify(jws, key, options) {
    if (jws instanceof Uint8Array) {
        jws = decoder.decode(jws);
    }
    if (typeof jws !== 'string') {
        throw new JWSInvalid('Compact JWS must be a string or Uint8Array');
    }
    const { 0: protectedHeader, 1: payload, 2: signature, length } = jws.split('.');
    if (length !== 3) {
        throw new JWSInvalid('Invalid Compact JWS');
    }
    const verified = await flattenedVerify({ payload, protected: protectedHeader, signature }, key, options);
    const result = { payload: verified.payload, protectedHeader: verified.protectedHeader };
    if (typeof key === 'function') {
        return { ...result, key: verified.key };
    }
    return result;
}

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/lib/jwt_claims_set.js





const normalizeTyp = (value) => value.toLowerCase().replace(/^application\//, '');
const checkAudiencePresence = (audPayload, audOption) => {
    if (typeof audPayload === 'string') {
        return audOption.includes(audPayload);
    }
    if (Array.isArray(audPayload)) {
        return audOption.some(Set.prototype.has.bind(new Set(audPayload)));
    }
    return false;
};
/* harmony default export */ const jwt_claims_set = ((protectedHeader, encodedPayload, options = {}) => {
    let payload;
    try {
        payload = JSON.parse(decoder.decode(encodedPayload));
    }
    catch {
    }
    if (!isObject(payload)) {
        throw new JWTInvalid('JWT Claims Set must be a top-level JSON object');
    }
    const { typ } = options;
    if (typ &&
        (typeof protectedHeader.typ !== 'string' ||
            normalizeTyp(protectedHeader.typ) !== normalizeTyp(typ))) {
        throw new JWTClaimValidationFailed('unexpected "typ" JWT header value', payload, 'typ', 'check_failed');
    }
    const { requiredClaims = [], issuer, subject, audience, maxTokenAge } = options;
    const presenceCheck = [...requiredClaims];
    if (maxTokenAge !== undefined)
        presenceCheck.push('iat');
    if (audience !== undefined)
        presenceCheck.push('aud');
    if (subject !== undefined)
        presenceCheck.push('sub');
    if (issuer !== undefined)
        presenceCheck.push('iss');
    for (const claim of new Set(presenceCheck.reverse())) {
        if (!(claim in payload)) {
            throw new JWTClaimValidationFailed(`missing required "${claim}" claim`, payload, claim, 'missing');
        }
    }
    if (issuer &&
        !(Array.isArray(issuer) ? issuer : [issuer]).includes(payload.iss)) {
        throw new JWTClaimValidationFailed('unexpected "iss" claim value', payload, 'iss', 'check_failed');
    }
    if (subject && payload.sub !== subject) {
        throw new JWTClaimValidationFailed('unexpected "sub" claim value', payload, 'sub', 'check_failed');
    }
    if (audience &&
        !checkAudiencePresence(payload.aud, typeof audience === 'string' ? [audience] : audience)) {
        throw new JWTClaimValidationFailed('unexpected "aud" claim value', payload, 'aud', 'check_failed');
    }
    let tolerance;
    switch (typeof options.clockTolerance) {
        case 'string':
            tolerance = secs(options.clockTolerance);
            break;
        case 'number':
            tolerance = options.clockTolerance;
            break;
        case 'undefined':
            tolerance = 0;
            break;
        default:
            throw new TypeError('Invalid clockTolerance option type');
    }
    const { currentDate } = options;
    const now = epoch(currentDate || new Date());
    if ((payload.iat !== undefined || maxTokenAge) && typeof payload.iat !== 'number') {
        throw new JWTClaimValidationFailed('"iat" claim must be a number', payload, 'iat', 'invalid');
    }
    if (payload.nbf !== undefined) {
        if (typeof payload.nbf !== 'number') {
            throw new JWTClaimValidationFailed('"nbf" claim must be a number', payload, 'nbf', 'invalid');
        }
        if (payload.nbf > now + tolerance) {
            throw new JWTClaimValidationFailed('"nbf" claim timestamp check failed', payload, 'nbf', 'check_failed');
        }
    }
    if (payload.exp !== undefined) {
        if (typeof payload.exp !== 'number') {
            throw new JWTClaimValidationFailed('"exp" claim must be a number', payload, 'exp', 'invalid');
        }
        if (payload.exp <= now - tolerance) {
            throw new JWTExpired('"exp" claim timestamp check failed', payload, 'exp', 'check_failed');
        }
    }
    if (maxTokenAge) {
        const age = now - payload.iat;
        const max = typeof maxTokenAge === 'number' ? maxTokenAge : secs(maxTokenAge);
        if (age - tolerance > max) {
            throw new JWTExpired('"iat" claim timestamp check failed (too far in the past)', payload, 'iat', 'check_failed');
        }
        if (age < 0 - tolerance) {
            throw new JWTClaimValidationFailed('"iat" claim timestamp check failed (it should be in the past)', payload, 'iat', 'check_failed');
        }
    }
    return payload;
});

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/jwt/verify.js



async function jwtVerify(jwt, key, options) {
    const verified = await compactVerify(jwt, key, options);
    if (verified.protectedHeader.crit?.includes('b64') && verified.protectedHeader.b64 === false) {
        throw new JWTInvalid('JWTs MUST NOT use unencoded payload');
    }
    const payload = jwt_claims_set(verified.protectedHeader, verified.payload, options);
    const result = { payload, protectedHeader: verified.protectedHeader };
    if (typeof key === 'function') {
        return { ...result, key: verified.key };
    }
    return result;
}

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/runtime/digest.js

const digest_digest = async (algorithm, data) => {
    const subtleDigest = `SHA-${algorithm.slice(-3)}`;
    return new Uint8Array(await webcrypto.subtle.digest(subtleDigest, data));
};
/* harmony default export */ const runtime_digest = (digest_digest);

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/jwk/thumbprint.js





const check = (value, description) => {
    if (typeof value !== 'string' || !value) {
        throw new JWKInvalid(`${description} missing or invalid`);
    }
};
async function calculateJwkThumbprint(jwk, digestAlgorithm) {
    if (!isObject(jwk)) {
        throw new TypeError('JWK must be an object');
    }
    digestAlgorithm ?? (digestAlgorithm = 'sha256');
    if (digestAlgorithm !== 'sha256' &&
        digestAlgorithm !== 'sha384' &&
        digestAlgorithm !== 'sha512') {
        throw new TypeError('digestAlgorithm must one of "sha256", "sha384", or "sha512"');
    }
    let components;
    switch (jwk.kty) {
        case 'EC':
            check(jwk.crv, '"crv" (Curve) Parameter');
            check(jwk.x, '"x" (X Coordinate) Parameter');
            check(jwk.y, '"y" (Y Coordinate) Parameter');
            components = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
            break;
        case 'OKP':
            check(jwk.crv, '"crv" (Subtype of Key Pair) Parameter');
            check(jwk.x, '"x" (Public Key) Parameter');
            components = { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
            break;
        case 'RSA':
            check(jwk.e, '"e" (Exponent) Parameter');
            check(jwk.n, '"n" (Modulus) Parameter');
            components = { e: jwk.e, kty: jwk.kty, n: jwk.n };
            break;
        case 'oct':
            check(jwk.k, '"k" (Key Value) Parameter');
            components = { k: jwk.k, kty: jwk.kty };
            break;
        default:
            throw new errors_JOSENotSupported('"kty" (Key Type) Parameter missing or unsupported');
    }
    const data = encoder.encode(JSON.stringify(components));
    return encode(await runtime_digest(digestAlgorithm, data));
}
async function calculateJwkThumbprintUri(jwk, digestAlgorithm) {
    digestAlgorithm ?? (digestAlgorithm = 'sha256');
    const thumbprint = await calculateJwkThumbprint(jwk, digestAlgorithm);
    return `urn:ietf:params:oauth:jwk-thumbprint:sha-${digestAlgorithm.slice(-3)}:${thumbprint}`;
}

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/runtime/generate.js



async function generateSecret(alg, options) {
    let length;
    let algorithm;
    let keyUsages;
    switch (alg) {
        case 'HS256':
        case 'HS384':
        case 'HS512':
            length = parseInt(alg.slice(-3), 10);
            algorithm = { name: 'HMAC', hash: `SHA-${length}`, length };
            keyUsages = ['sign', 'verify'];
            break;
        case 'A128CBC-HS256':
        case 'A192CBC-HS384':
        case 'A256CBC-HS512':
            length = parseInt(alg.slice(-3), 10);
            return random(new Uint8Array(length >> 3));
        case 'A128KW':
        case 'A192KW':
        case 'A256KW':
            length = parseInt(alg.slice(1, 4), 10);
            algorithm = { name: 'AES-KW', length };
            keyUsages = ['wrapKey', 'unwrapKey'];
            break;
        case 'A128GCMKW':
        case 'A192GCMKW':
        case 'A256GCMKW':
        case 'A128GCM':
        case 'A192GCM':
        case 'A256GCM':
            length = parseInt(alg.slice(1, 4), 10);
            algorithm = { name: 'AES-GCM', length };
            keyUsages = ['encrypt', 'decrypt'];
            break;
        default:
            throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
    }
    return crypto.subtle.generateKey(algorithm, options?.extractable ?? false, keyUsages);
}
function getModulusLengthOption(options) {
    const modulusLength = options?.modulusLength ?? 2048;
    if (typeof modulusLength !== 'number' || modulusLength < 2048) {
        throw new errors_JOSENotSupported('Invalid or unsupported modulusLength option provided, 2048 bits or larger keys must be used');
    }
    return modulusLength;
}
async function generateKeyPair(alg, options) {
    let algorithm;
    let keyUsages;
    switch (alg) {
        case 'PS256':
        case 'PS384':
        case 'PS512':
            algorithm = {
                name: 'RSA-PSS',
                hash: `SHA-${alg.slice(-3)}`,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                modulusLength: getModulusLengthOption(options),
            };
            keyUsages = ['sign', 'verify'];
            break;
        case 'RS256':
        case 'RS384':
        case 'RS512':
            algorithm = {
                name: 'RSASSA-PKCS1-v1_5',
                hash: `SHA-${alg.slice(-3)}`,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                modulusLength: getModulusLengthOption(options),
            };
            keyUsages = ['sign', 'verify'];
            break;
        case 'RSA-OAEP':
        case 'RSA-OAEP-256':
        case 'RSA-OAEP-384':
        case 'RSA-OAEP-512':
            algorithm = {
                name: 'RSA-OAEP',
                hash: `SHA-${parseInt(alg.slice(-3), 10) || 1}`,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                modulusLength: getModulusLengthOption(options),
            };
            keyUsages = ['decrypt', 'unwrapKey', 'encrypt', 'wrapKey'];
            break;
        case 'ES256':
            algorithm = { name: 'ECDSA', namedCurve: 'P-256' };
            keyUsages = ['sign', 'verify'];
            break;
        case 'ES384':
            algorithm = { name: 'ECDSA', namedCurve: 'P-384' };
            keyUsages = ['sign', 'verify'];
            break;
        case 'ES512':
            algorithm = { name: 'ECDSA', namedCurve: 'P-521' };
            keyUsages = ['sign', 'verify'];
            break;
        case 'Ed25519':
            algorithm = { name: 'Ed25519' };
            keyUsages = ['sign', 'verify'];
            break;
        case 'EdDSA': {
            keyUsages = ['sign', 'verify'];
            const crv = options?.crv ?? 'Ed25519';
            switch (crv) {
                case 'Ed25519':
                case 'Ed448':
                    algorithm = { name: crv };
                    break;
                default:
                    throw new errors_JOSENotSupported('Invalid or unsupported crv option provided');
            }
            break;
        }
        case 'ECDH-ES':
        case 'ECDH-ES+A128KW':
        case 'ECDH-ES+A192KW':
        case 'ECDH-ES+A256KW': {
            keyUsages = ['deriveKey', 'deriveBits'];
            const crv = options?.crv ?? 'P-256';
            switch (crv) {
                case 'P-256':
                case 'P-384':
                case 'P-521': {
                    algorithm = { name: 'ECDH', namedCurve: crv };
                    break;
                }
                case 'X25519':
                case 'X448':
                    algorithm = { name: crv };
                    break;
                default:
                    throw new errors_JOSENotSupported('Invalid or unsupported crv option provided, supported values are P-256, P-384, P-521, X25519, and X448');
            }
            break;
        }
        default:
            throw new errors_JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
    }
    return webcrypto.subtle.generateKey(algorithm, options?.extractable ?? false, keyUsages);
}

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/key/generate_key_pair.js

async function generate_key_pair_generateKeyPair(alg, options) {
    return generateKeyPair(alg, options);
}

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/util/base64url.js

const base64url_encode = encode;
const base64url_decode = decode;

;// ./node_modules/solid-oidc/node_modules/jose/dist/browser/util/decode_jwt.js




function decodeJwt(jwt) {
    if (typeof jwt !== 'string')
        throw new JWTInvalid('JWTs must use Compact JWS serialization, JWT must be a string');
    const { 1: payload, length } = jwt.split('.');
    if (length === 5)
        throw new JWTInvalid('Only JWTs using Compact JWS serialization can be decoded');
    if (length !== 3)
        throw new JWTInvalid('Invalid JWT');
    if (!payload)
        throw new JWTInvalid('JWTs must contain a payload');
    let decoded;
    try {
        decoded = base64url_decode(payload);
    }
    catch {
        throw new JWTInvalid('Failed to base64url decode the payload');
    }
    let result;
    try {
        result = JSON.parse(decoder.decode(decoded));
    }
    catch {
        throw new JWTInvalid('Failed to parse the decoded payload as JSON');
    }
    if (!isObject(result))
        throw new JWTInvalid('Invalid JWT Claims Set');
    return result;
}

;// ./node_modules/solid-oidc/solid-oidc.js
/**
 * solid-oidc.js - Minimal Solid-OIDC client for browsers
 *
 * A zero-build, single-file Solid-OIDC authentication library.
 *
 * @license MIT
 * @author JavaScriptSolidServer
 * @see https://github.com/JavaScriptSolidServer/solid-oidc
 *
 * Based on solid-oidc-client-browser by uvdsl (Christoph Braun)
 * @see https://github.com/uvdsl/solid-oidc-client-browser
 *
 * Implements:
 * - RFC 6749 - OAuth 2.0
 * - RFC 7636 - PKCE
 * - RFC 9207 - OAuth 2.0 Authorization Server Issuer Identification
 * - RFC 9449 - DPoP (Demonstration of Proof-of-Possession)
 * - Solid-OIDC Specification
 */



// ============================================================================
// Session Events
// ============================================================================

const SessionEvents = {
  STATE_CHANGE: 'sessionStateChange',
  EXPIRATION_WARNING: 'sessionExpirationWarning',
  EXPIRATION: 'sessionExpiration'
}

// ============================================================================
// Session Database Interface (IndexedDB Implementation)
// ============================================================================

class SessionDatabase {
  constructor(dbName = 'solid-oidc', storeName = 'session', dbVersion = 1) {
    this.dbName = dbName
    this.storeName = storeName
    this.dbVersion = dbVersion
    this.db = null
  }

  async init() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, this.dbVersion)
      request.onerror = () => reject(new Error(`Database error: ${request.error}`))
      request.onsuccess = () => {
        this.db = request.result
        resolve(this)
      }
      request.onupgradeneeded = (event) => {
        const db = event.target.result
        if (!db.objectStoreNames.contains(this.storeName)) {
          db.createObjectStore(this.storeName)
        }
      }
    })
  }

  async setItem(id, value) {
    if (!this.db) await this.init()
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(this.storeName, 'readwrite')
      tx.oncomplete = () => resolve()
      tx.onerror = () => reject(new Error(`Transaction error: ${tx.error}`))
      tx.objectStore(this.storeName).put(value, id)
    })
  }

  async getItem(id) {
    if (!this.db) await this.init()
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(this.storeName, 'readonly')
      tx.onerror = () => reject(new Error(`Transaction error: ${tx.error}`))
      const request = tx.objectStore(this.storeName).get(id)
      request.onsuccess = () => resolve(request.result || null)
    })
  }

  async deleteItem(id) {
    if (!this.db) await this.init()
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(this.storeName, 'readwrite')
      tx.oncomplete = () => resolve()
      tx.onerror = () => reject(new Error(`Transaction error: ${tx.error}`))
      tx.objectStore(this.storeName).delete(id)
    })
  }

  async clear() {
    if (!this.db) await this.init()
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(this.storeName, 'readwrite')
      tx.oncomplete = () => resolve()
      tx.onerror = () => reject(new Error(`Transaction error: ${tx.error}`))
      tx.objectStore(this.storeName).clear()
    })
  }

  close() {
    if (this.db) {
      this.db.close()
      this.db = null
    }
  }
}

// ============================================================================
// PKCE Helper (RFC 7636)
// ============================================================================

async function generatePKCE() {
  const verifier = crypto.randomUUID() + '-' + crypto.randomUUID()
  const digest = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  )
  const challenge = btoa(String.fromCharCode(...digest))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
  return { verifier, challenge }
}

// ============================================================================
// DPoP Helper (RFC 9449)
// ============================================================================

async function createDPoPToken(keyPair, htu, htm, ath = null) {
  const publicJwk = await exportJWK(keyPair.publicKey)
  const payload = { htu, htm }
  if (ath) payload.ath = ath

  return new SignJWT(payload)
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
    .sign(keyPair.privateKey)
}

async function computeAth(accessToken) {
  const data = new TextEncoder().encode(accessToken)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return btoa(String.fromCharCode(...hashArray))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

// ============================================================================
// OIDC Discovery
// ============================================================================

async function discoverOIDC(idp) {
  const origin = new URL(idp).origin
  const response = await fetch(`${origin}/.well-known/openid-configuration`)
  if (!response.ok) throw new Error(`OIDC discovery failed: ${response.status}`)
  return response.json()
}

// ============================================================================
// Dynamic Client Registration
// ============================================================================

async function registerClient(registrationEndpoint, redirectUris) {
  const response = await fetch(registrationEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      application_type: 'web',
      redirect_uris: redirectUris,
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      scope: 'openid offline_access webid'
    })
  })
  if (!response.ok) throw new Error(`Client registration failed: ${response.status}`)
  return response.json()
}

// ============================================================================
// Token Request
// ============================================================================

async function requestTokens(tokenEndpoint, params, keyPair) {
  const dpop = await createDPoPToken(keyPair, tokenEndpoint, 'POST')
  const response = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'DPoP': dpop
    },
    body: new URLSearchParams(params)
  })
  if (!response.ok) throw new Error(`Token request failed: ${response.status}`)
  return response.json()
}

// ============================================================================
// Token Validation
// ============================================================================

async function validateAccessToken(accessToken, jwksUri, issuer, clientId, keyPair) {
  const jwks = createRemoteJWKSet(new URL(jwksUri))
  const { payload } = await jwtVerify(accessToken, jwks, {
    issuer,
    audience: 'solid'
  })

  // Verify DPoP binding
  const thumbprint = await calculateJwkThumbprint(await exportJWK(keyPair.publicKey))
  if (payload.cnf?.jkt !== thumbprint) {
    throw new Error('DPoP thumbprint mismatch')
  }

  // Verify client_id
  if (payload.client_id !== clientId) {
    throw new Error('client_id mismatch')
  }

  return payload
}

// ============================================================================
// Refresh Token Grant
// ============================================================================

async function refreshTokens(database) {
  await database.init()

  const [refreshToken, tokenEndpoint, clientId, keyPair] = await Promise.all([
    database.getItem('refresh_token'),
    database.getItem('token_endpoint'),
    database.getItem('client_id'),
    database.getItem('dpop_keypair')
  ])

  if (!refreshToken || !tokenEndpoint || !clientId || !keyPair) {
    throw new Error('Missing refresh data')
  }

  const tokens = await requestTokens(tokenEndpoint, {
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: clientId
  }, keyPair)

  // Persist new refresh token if provided
  if (tokens.refresh_token) {
    await database.setItem('refresh_token', tokens.refresh_token)
  }

  database.close()
  return { ...tokens, dpop_key_pair: keyPair }
}

// ============================================================================
// Main Session Class
// ============================================================================

class solid_oidc_Session extends EventTarget {
  constructor(options = {}) {
    super()
    this.clientId = options.clientId || null
    this.database = options.database || new SessionDatabase()
    this.onStateChange = options.onStateChange || null
    this.onExpirationWarning = options.onExpirationWarning || null
    this.onExpiration = options.onExpiration || null

    // Internal state
    this._isActive = false
    this._webId = null
    this._exp = null
    this._ath = null
    this._tokens = null
    this._idpDetails = null
    this._refreshPromise = null

    // Set up event listeners
    if (this.onStateChange) {
      this.addEventListener(SessionEvents.STATE_CHANGE, this.onStateChange)
    }
    if (this.onExpirationWarning) {
      this.addEventListener(SessionEvents.EXPIRATION_WARNING, this.onExpirationWarning)
    }
    if (this.onExpiration) {
      this.addEventListener(SessionEvents.EXPIRATION, this.onExpiration)
    }
  }

  // ==========================================================================
  // Public API
  // ==========================================================================

  get isActive() { return this._isActive }
  get webId() { return this._webId }

  isExpired() {
    if (!this._exp) return true
    return Math.floor(Date.now() / 1000) >= this._exp
  }

  getExpiresIn() {
    if (!this._exp) return -1
    return this._exp - Math.floor(Date.now() / 1000)
  }

  /**
   * Redirect user to identity provider for login
   */
  async login(idp, redirectUri) {
    // Sanitize redirect URI (RFC 6749 Section 3.1.2)
    const redirectUrl = new URL(redirectUri)
    const sanitizedRedirect = redirectUrl.origin + redirectUrl.pathname + redirectUrl.search

    // OIDC Discovery
    const config = await discoverOIDC(idp)

    // RFC 9207: Verify issuer
    const issuer = config.issuer
    const trimSlash = (s) => s.endsWith('/') ? s.slice(0, -1) : s
    if (trimSlash(idp) !== trimSlash(issuer)) {
      throw new Error(`Issuer mismatch: ${issuer} !== ${idp}`)
    }

    // Store IDP details
    sessionStorage.setItem('solid_oidc_idp', issuer)
    sessionStorage.setItem('solid_oidc_token_endpoint', config.token_endpoint)
    sessionStorage.setItem('solid_oidc_jwks_uri', config.jwks_uri)

    // Get or register client_id
    let clientId = this.clientId
    if (!clientId) {
      const registration = await registerClient(config.registration_endpoint, [sanitizedRedirect])
      clientId = registration.client_id
      sessionStorage.setItem('solid_oidc_client_id', clientId)
    }

    // PKCE (RFC 7636)
    const pkce = await generatePKCE()
    sessionStorage.setItem('solid_oidc_pkce_verifier', pkce.verifier)

    // CSRF token
    const csrfToken = crypto.randomUUID()
    sessionStorage.setItem('solid_oidc_csrf', csrfToken)

    // Build authorization URL
    const authUrl = new URL(config.authorization_endpoint)
    authUrl.searchParams.set('response_type', 'code')
    authUrl.searchParams.set('redirect_uri', sanitizedRedirect)
    authUrl.searchParams.set('scope', 'openid offline_access webid')
    authUrl.searchParams.set('client_id', clientId)
    authUrl.searchParams.set('code_challenge_method', 'S256')
    authUrl.searchParams.set('code_challenge', pkce.challenge)
    authUrl.searchParams.set('state', csrfToken)
    authUrl.searchParams.set('prompt', 'consent')

    // Redirect to IDP
    window.location.href = authUrl.toString()
  }

  /**
   * Handle redirect from identity provider after login
   */
  async handleRedirectFromLogin() {
    const url = new URL(window.location.href)
    const code = url.searchParams.get('code')

    // No code = not a redirect, nothing to do
    if (!code) return

    // RFC 9207: Verify issuer
    const idp = sessionStorage.getItem('solid_oidc_idp')
    const iss = url.searchParams.get('iss')
    if (!idp || iss !== idp) {
      throw new Error(`Issuer mismatch: ${iss} !== ${idp}`)
    }

    // RFC 6749: Verify CSRF token
    const csrf = sessionStorage.getItem('solid_oidc_csrf')
    if (url.searchParams.get('state') !== csrf) {
      throw new Error('CSRF token mismatch')
    }

    // Clean URL
    url.searchParams.delete('code')
    url.searchParams.delete('iss')
    url.searchParams.delete('state')
    window.history.replaceState({}, document.title, url.toString())

    // Get stored values
    const pkceVerifier = sessionStorage.getItem('solid_oidc_pkce_verifier')
    const tokenEndpoint = sessionStorage.getItem('solid_oidc_token_endpoint')
    const jwksUri = sessionStorage.getItem('solid_oidc_jwks_uri')
    const clientId = this.clientId || sessionStorage.getItem('solid_oidc_client_id')

    if (!pkceVerifier || !tokenEndpoint || !clientId) {
      throw new Error('Missing session data')
    }

    // Generate DPoP key pair
    const keyPair = await generate_key_pair_generateKeyPair('ES256')

    // Exchange code for tokens
    const tokens = await requestTokens(tokenEndpoint, {
      grant_type: 'authorization_code',
      code,
      code_verifier: pkceVerifier,
      redirect_uri: url.origin + url.pathname,
      client_id: clientId
    }, keyPair)

    // Validate access token
    await validateAccessToken(tokens.access_token, jwksUri, idp, clientId, keyPair)

    // Store IDP details
    this._idpDetails = { idp, jwksUri, tokenEndpoint }

    // Persist for refresh
    await this.database.init()
    await Promise.all([
      this.database.setItem('idp', idp),
      this.database.setItem('jwks_uri', jwksUri),
      this.database.setItem('token_endpoint', tokenEndpoint),
      this.database.setItem('client_id', clientId),
      this.database.setItem('dpop_keypair', keyPair),
      this.database.setItem('refresh_token', tokens.refresh_token)
    ])
    this.database.close()

    // Clean session storage
    sessionStorage.removeItem('solid_oidc_idp')
    sessionStorage.removeItem('solid_oidc_token_endpoint')
    sessionStorage.removeItem('solid_oidc_jwks_uri')
    sessionStorage.removeItem('solid_oidc_client_id')
    sessionStorage.removeItem('solid_oidc_pkce_verifier')
    sessionStorage.removeItem('solid_oidc_csrf')

    // Update session state
    await this._setTokens({ ...tokens, dpop_key_pair: keyPair })
    this._dispatchStateChange()
  }

  /**
   * Restore session using stored refresh token
   */
  async restore() {
    if (this._refreshPromise) return this._refreshPromise

    this._refreshPromise = (async () => {
      try {
        const tokens = await refreshTokens(this.database)
        await this._setTokens(tokens)
        this._dispatchStateChange()
      } catch (error) {
        if (this._isActive) {
          if (!this.isExpired()) {
            this._dispatchExpirationWarning()
          } else {
            this._dispatchExpiration()
          }
        }
        throw error
      } finally {
        this._refreshPromise = null
      }
    })()

    return this._refreshPromise
  }

  /**
   * Log out and clear all session data
   */
  async logout() {
    this._isActive = false
    this._webId = null
    this._exp = null
    this._ath = null
    this._tokens = null
    this._idpDetails = null

    await this.database.init()
    await this.database.clear()
    this.database.close()

    this._dispatchStateChange()
  }

  /**
   * Make authenticated fetch request with DPoP
   */
  async authFetch(input, init = {}) {
    // No session = regular fetch
    if (!this._isActive) {
      return fetch(input, init)
    }

    // Refresh if expired
    if (this.isExpired()) {
      await this.restore()
    }

    // Parse request
    let url, method, headers
    if (input instanceof Request) {
      url = new URL(input.url)
      method = init.method || input.method || 'GET'
      headers = new Headers(input.headers)
    } else {
      url = new URL(input.toString())
      method = init.method || 'GET'
      headers = init.headers ? new Headers(init.headers) : new Headers()
    }

    // Create DPoP proof
    const dpop = await createDPoPToken(
      this._tokens.dpop_key_pair,
      `${url.origin}${url.pathname}`,
      method.toUpperCase(),
      this._ath
    )

    // Set auth headers
    headers.set('DPoP', dpop)
    headers.set('Authorization', `DPoP ${this._tokens.access_token}`)

    // Make request
    if (input instanceof Request) {
      return fetch(new Request(input, { ...init, headers }))
    }
    return fetch(url, { ...init, headers })
  }

  // ==========================================================================
  // Internal Methods
  // ==========================================================================

  async _setTokens(tokens) {
    this._tokens = tokens

    const decoded = decodeJwt(tokens.access_token)
    if (!decoded.webid) throw new Error('Missing webid claim')
    if (!decoded.exp) throw new Error('Missing exp claim')

    this._ath = await computeAth(tokens.access_token)
    this._webId = decoded.webid
    this._exp = decoded.exp
    this._isActive = true
  }

  _dispatchStateChange() {
    this.dispatchEvent(new CustomEvent(SessionEvents.STATE_CHANGE, {
      detail: { isActive: this._isActive, webId: this._webId }
    }))
  }

  _dispatchExpirationWarning() {
    this.dispatchEvent(new CustomEvent(SessionEvents.EXPIRATION_WARNING, {
      detail: { expires_in: this.getExpiresIn() }
    }))
  }

  _dispatchExpiration() {
    this.dispatchEvent(new CustomEvent(SessionEvents.EXPIRATION))
  }
}

// ============================================================================
// Default Export
// ============================================================================

/* harmony default export */ const solid_oidc = ((/* unused pure expression or super */ null && (solid_oidc_Session)));

;// ./src/authSession/solidOidcAdapter.ts
/**
 * Adapter to make solid-oidc compatible with @inrupt/solid-client-authn-browser API
 *
 * This provides a drop-in replacement for the Inrupt Session class using the minimal
 * solid-oidc library from JavaScriptSolidServer.
 *
 * @see https://github.com/JavaScriptSolidServer/solid-oidc
 */

/**
 * Event names compatible with @inrupt/solid-client-authn-browser
 */
const EVENTS = {
    SESSION_RESTORED: 'sessionRestore',
    LOGIN: 'login',
    LOGOUT: 'logout',
    SESSION_EXPIRED: 'sessionExpired',
    ERROR: 'error'
};
/**
 * Simple event emitter for compatibility with Inrupt's session.events API
 */
class EventEmitter {
    constructor() {
        this.listeners = new Map();
    }
    on(event, callback) {
        if (!this.listeners.has(event)) {
            this.listeners.set(event, new Set());
        }
        this.listeners.get(event).add(callback);
    }
    off(event, callback) {
        var _a;
        (_a = this.listeners.get(event)) === null || _a === void 0 ? void 0 : _a.delete(callback);
    }
    emit(event, ...args) {
        var _a;
        (_a = this.listeners.get(event)) === null || _a === void 0 ? void 0 : _a.forEach(cb => cb(...args));
    }
}
/**
 * Session class that wraps solid-oidc to provide @inrupt/solid-client-authn-browser compatible API
 */
class Session {
    constructor(options) {
        this._session = new solid_oidc_Session({
            clientId: options === null || options === void 0 ? void 0 : options.clientId,
            database: new SessionDatabase(),
            onStateChange: (event) => {
                const detail = event.detail;
                if (detail === null || detail === void 0 ? void 0 : detail.isActive) {
                    this._events.emit(EVENTS.LOGIN);
                    this._events.emit(EVENTS.SESSION_RESTORED, window.location.href);
                }
                else {
                    this._events.emit(EVENTS.LOGOUT);
                }
            },
            onExpiration: () => {
                this._events.emit(EVENTS.SESSION_EXPIRED);
            }
        });
        this._events = new EventEmitter();
        this._sessionId = crypto.randomUUID();
    }
    /**
     * Event emitter for session events
     */
    get events() {
        return this._events;
    }
    /**
     * Session information
     */
    get info() {
        var _a;
        return {
            isLoggedIn: this._session.isActive,
            webId: (_a = this._session.webId) !== null && _a !== void 0 ? _a : undefined,
            sessionId: this._sessionId,
            expirationDate: this._session.isActive
                ? Date.now() + (this._session.getExpiresIn() * 1000)
                : undefined
        };
    }
    /**
     * Handle incoming redirect from identity provider
     */
    async handleIncomingRedirect(options) {
        // Handle string URL (legacy API)
        const opts = typeof options === 'string'
            ? { url: options }
            : options !== null && options !== void 0 ? options : {};
        try {
            // First handle any redirect from login
            await this._session.handleRedirectFromLogin();
            // If not logged in and restorePreviousSession is true, try to restore
            if (!this._session.isActive && opts.restorePreviousSession !== false) {
                try {
                    await this._session.restore();
                }
                catch {
                    // No session to restore, that's okay
                }
            }
            return this.info;
        }
        catch (error) {
            this._events.emit(EVENTS.ERROR, error);
            return undefined;
        }
    }
    /**
     * Initiate login flow
     */
    async login(options) {
        const redirectUrl = options.redirectUrl || window.location.href;
        await this._session.login(options.oidcIssuer, redirectUrl);
    }
    /**
     * Log out and clear session
     */
    async logout() {
        await this._session.logout();
    }
    /**
     * Make authenticated fetch request
     */
    async fetch(url, init) {
        return this._session.authFetch(url, init);
    }
}
/* harmony default export */ const solidOidcAdapter = ((/* unused pure expression or super */ null && (Session)));

;// ./src/authSession/authSession.ts

const authSession = new Session();

// EXTERNAL MODULE: external "$rdf"
var external_$rdf_ = __webpack_require__(264);
// EXTERNAL MODULE: ./node_modules/solid-namespace/index.js
var solid_namespace = __webpack_require__(386);
var solid_namespace_default = /*#__PURE__*/__webpack_require__.n(solid_namespace);
;// ./src/util/ns.ts
// Namespaces we commonly use and have common prefixes for around Solid
 // Delegate to this which takes RDFlib as param.

const ns_ns = solid_namespace_default()(external_$rdf_);

;// ./src/acl/aclLogic.ts


const ACL_LINK = (0,external_$rdf_.sym)('http://www.iana.org/assignments/link-relations/acl');
function createAclLogic(store) {
    const ns = ns_ns;
    async function findAclDocUrl(url) {
        await store.fetcher.load(url);
        const docNode = store.any(url, ACL_LINK);
        if (!docNode) {
            throw new Error(`No ACL link discovered for ${url}`);
        }
        return docNode.value;
    }
    /**
     * Simple Access Control
     *
     * This function sets up a simple default ACL for a resource, with
     * RWC for the owner, and a specified access (default none) for the public.
     * In all cases owner has read write control.
     * Parameter lists modes allowed to public
     *
     * @param options
     * @param options.public eg ['Read', 'Write']
     *
     * @returns Resolves with aclDoc uri on successful write
     */
    function setACLUserPublic(docURI, me, options) {
        const aclDoc = store.any(store.sym(docURI), ACL_LINK);
        return Promise.resolve()
            .then(() => {
            if (aclDoc) {
                return aclDoc;
            }
            return fetchACLRel(docURI).catch(err => {
                throw new Error(`Error fetching rel=ACL header for ${docURI}: ${err}`);
            });
        })
            .then(aclDoc => {
            const aclText = genACLText(docURI, me, aclDoc.uri, options);
            if (!store.fetcher) {
                throw new Error('Cannot PUT this, store has no fetcher');
            }
            return store.fetcher
                .webOperation('PUT', aclDoc.uri, {
                data: aclText,
                contentType: 'text/turtle'
            })
                .then(result => {
                if (!result.ok) {
                    throw new Error('Error writing ACL text: ' + result.error);
                }
                return aclDoc;
            });
        });
    }
    /**
     * @param docURI
     * @returns
     */
    function fetchACLRel(docURI) {
        const fetcher = store.fetcher;
        if (!fetcher) {
            throw new Error('Cannot fetch ACL rel, store has no fetcher');
        }
        return fetcher.load(docURI).then(result => {
            if (!result.ok) {
                throw new Error('fetchACLRel: While loading:' + result.error);
            }
            const aclDoc = store.any(store.sym(docURI), ACL_LINK);
            if (!aclDoc) {
                throw new Error('fetchACLRel: No Link rel=ACL header for ' + docURI);
            }
            return aclDoc;
        });
    }
    /**
     * @param docURI
     * @param me
     * @param aclURI
     * @param options
     *
     * @returns Serialized ACL
     */
    function genACLText(docURI, me, aclURI, options = {}) {
        const optPublic = options.public || [];
        const g = (0,external_$rdf_.graph)();
        const auth = (0,external_$rdf_.Namespace)('http://www.w3.org/ns/auth/acl#');
        let a = g.sym(`${aclURI}#a1`);
        const acl = g.sym(aclURI);
        const doc = g.sym(docURI);
        g.add(a, ns.rdf('type'), auth('Authorization'), acl);
        g.add(a, auth('accessTo'), doc, acl);
        if (options.defaultForNew) {
            g.add(a, auth('default'), doc, acl);
        }
        g.add(a, auth('agent'), me, acl);
        g.add(a, auth('mode'), auth('Read'), acl);
        g.add(a, auth('mode'), auth('Write'), acl);
        g.add(a, auth('mode'), auth('Control'), acl);
        if (optPublic.length) {
            a = g.sym(`${aclURI}#a2`);
            g.add(a, ns.rdf('type'), auth('Authorization'), acl);
            g.add(a, auth('accessTo'), doc, acl);
            g.add(a, auth('agentClass'), ns.foaf('Agent'), acl);
            for (let p = 0; p < optPublic.length; p++) {
                g.add(a, auth('mode'), auth(optPublic[p]), acl); // Like 'Read' etc
            }
        }
        return (0,external_$rdf_.serialize)(acl, g, aclURI);
    }
    return {
        findAclDocUrl,
        setACLUserPublic,
        genACLText
    };
}

;// ./src/authn/authUtil.ts


/**
 * find a user or app's context as set in window.SolidAppContext
 * this is a const, not a function, because we have problems to jest mock it otherwise
 * see: https://github.com/facebook/jest/issues/936#issuecomment-545080082 for more
 * @return {any} - an appContext object
 */
const appContext = () => {
    let { SolidAppContext } = window;
    SolidAppContext || (SolidAppContext = {});
    SolidAppContext.viewingNoAuthPage = false;
    if (SolidAppContext.noAuth && window.document) {
        const currentPage = window.document.location.href;
        if (currentPage.startsWith(SolidAppContext.noAuth)) {
            SolidAppContext.viewingNoAuthPage = true;
            const params = new URLSearchParams(window.document.location.search);
            if (params) {
                let viewedPage = SolidAppContext.viewedPage = params.get('uri') || null;
                if (viewedPage) {
                    viewedPage = decodeURI(viewedPage);
                    if (!viewedPage.startsWith(SolidAppContext.noAuth)) {
                        const ary = viewedPage.split(/\//);
                        SolidAppContext.idp = ary[0] + '//' + ary[2];
                        SolidAppContext.viewingNoAuthPage = false;
                    }
                }
            }
        }
    }
    return SolidAppContext;
};
/**
 * Returns `sym($SolidTestEnvironment.username)` if
 * `$SolidTestEnvironment.username` is defined as a global
 * or
 * returns testID defined in the HTML page
 * @returns {NamedNode|null}
 */
function offlineTestID() {
    const { $SolidTestEnvironment } = window;
    if (typeof $SolidTestEnvironment !== 'undefined' &&
        $SolidTestEnvironment.username) {
        // Test setup
        log('Assuming the user is ' + $SolidTestEnvironment.username);
        return (0,external_$rdf_.sym)($SolidTestEnvironment.username);
    }
    // hack that makes SolidOS work in offline mode by adding the webId directly in html
    // example usage: https://github.com/solidos/mashlib/blob/29b8b53c46bf02e0e219f0bacd51b0e9951001dd/test/contact/local.html#L37
    if (typeof document !== 'undefined' &&
        document.location &&
        ('' + document.location).slice(0, 16) === 'http://localhost') {
        const div = document.getElementById('appTarget');
        if (!div)
            return null;
        const id = div.getAttribute('testID');
        if (!id)
            return null;
        log('Assuming user is ' + id);
        return (0,external_$rdf_.sym)(id);
    }
    return null;
}

;// ./src/authn/SolidAuthnLogic.ts




class SolidAuthnLogic {
    constructor(solidAuthSession) {
        this.session = solidAuthSession;
    }
    // we created authSession getter because we want to access it as authn.authSession externally
    get authSession() { return this.session; }
    currentUser() {
        const app = appContext();
        if (app.viewingNoAuthPage) {
            return (0,external_$rdf_.sym)(app.webId);
        }
        if (this && this.session && this.session.info && this.session.info.webId && this.session.info.isLoggedIn) {
            return (0,external_$rdf_.sym)(this.session.info.webId);
        }
        return offlineTestID(); // null unless testing
    }
    /**
     * Retrieves currently logged in webId from either
     * defaultTestUser or SolidAuth
     * Also activates a session after login
     * @param [setUserCallback] Optional callback
     * @returns Resolves with webId uri, if no callback provided
     */
    async checkUser(setUserCallback) {
        // Save hash for "restorePreviousSession"
        const preLoginRedirectHash = new URL(window.location.href).hash;
        if (preLoginRedirectHash) {
            window.localStorage.setItem('preLoginRedirectHash', preLoginRedirectHash);
        }
        this.session.events.on(EVENTS.SESSION_RESTORED, (url) => {
            log(`Session restored to ${url}`);
            if (document.location.toString() !== url)
                history.replaceState(null, '', url);
        });
        /**
         * Handle a successful authentication redirect
         */
        const redirectUrl = new URL(window.location.href);
        redirectUrl.hash = '';
        await this.session
            .handleIncomingRedirect({
            restorePreviousSession: true,
            url: redirectUrl.href
        });
        // Check to see if a hash was stored in local storage
        const postLoginRedirectHash = window.localStorage.getItem('preLoginRedirectHash');
        if (postLoginRedirectHash) {
            const curUrl = new URL(window.location.href);
            if (curUrl.hash !== postLoginRedirectHash) {
                if (history.pushState) {
                    // debug.log('Setting window.location.has using pushState')
                    history.pushState(null, document.title, postLoginRedirectHash);
                }
                else {
                    // debug.warn('Setting window.location.has using location.hash')
                    location.hash = postLoginRedirectHash;
                }
                curUrl.hash = postLoginRedirectHash;
            }
            // See https://stackoverflow.com/questions/3870057/how-can-i-update-window-location-hash-without-jumping-the-document
            // window.location.href = curUrl.toString()// @@ See https://developer.mozilla.org/en-US/docs/Web/API/Window/location
            window.localStorage.setItem('preLoginRedirectHash', '');
        }
        // Check to see if already logged in / have the WebID
        let me = offlineTestID();
        if (me) {
            return Promise.resolve(setUserCallback ? setUserCallback(me) : me);
        }
        const webId = this.webIdFromSession(this.session.info);
        if (webId) {
            me = this.saveUser(webId);
        }
        if (me) {
            log(`(Logged in as ${me} by authentication)`);
        }
        return Promise.resolve(setUserCallback ? setUserCallback(me) : me);
    }
    /**
     * Saves `webId` in `context.me`
     * @param webId
     * @param context
     *
     * @returns Returns the WebID, after setting it
     */
    saveUser(webId, context) {
        let webIdUri;
        if (webId) {
            webIdUri = (typeof webId === 'string') ? webId : webId.uri;
            const me = (0,external_$rdf_.namedNode)(webIdUri);
            if (context) {
                context.me = me;
            }
            return me;
        }
        return null;
    }
    /**
     * @returns {Promise<string|null>} Resolves with WebID URI or null
     */
    webIdFromSession(session) {
        const webId = (session === null || session === void 0 ? void 0 : session.webId) && session.isLoggedIn ? session.webId : null;
        return webId;
    }
}

;// ./src/util/utils.ts

function newThing(doc) {
    return (0,external_$rdf_.sym)(doc.uri + '#' + 'id' + ('' + Date.now()));
}
function uniqueNodes(arr) {
    const uris = arr.map(x => x.uri);
    const set = new Set(uris);
    const uris2 = Array.from(set);
    const arr2 = uris2.map(u => new NamedNode(u));
    return arr2; // Array.from(new Set(arr.map(x => x.uri))).map(u => sym(u))
}
function getArchiveUrl(baseUrl, date) {
    const year = date.getUTCFullYear();
    const month = ('0' + (date.getUTCMonth() + 1)).slice(-2);
    const day = ('0' + (date.getUTCDate())).slice(-2);
    const parts = baseUrl.split('/');
    const filename = parts[parts.length - 1];
    return new URL(`./archive/${year}/${month}/${day}/${filename}`, baseUrl).toString();
}
function differentOrigin(doc) {
    if (!doc) {
        return true;
    }
    return (`${window.location.origin}/` !== new URL(doc.value).origin);
}
function suggestPreferencesFile(me) {
    const stripped = me.uri.replace('/profile/', '/').replace('/public/', '/');
    // const stripped = me.uri.replace(\/[p|P]rofile/\g, '/').replace(\/[p|P]ublic/\g, '/')
    const folderURI = stripped.split('/').slice(0, -1).join('/') + '/Settings/';
    const fileURI = folderURI + 'Preferences.ttl';
    return (0,external_$rdf_.sym)(fileURI);
}
function determineChatContainer(invitee, podRoot) {
    // Create chat
    // See https://gitter.im/solid/chat-app?at=5f3c800f855be416a23ae74a
    const chatContainerStr = new URL(`IndividualChats/${new URL(invitee.value).host}/`, podRoot.value).toString();
    return new external_$rdf_.NamedNode(chatContainerStr);
}

;// ./src/chat/chatLogic.ts



const CHAT_LOCATION_IN_CONTAINER = 'index.ttl#this';
function createChatLogic(store, profileLogic) {
    const ns = ns_ns;
    async function setAcl(chatContainer, me, invitee) {
        // Some servers don't present a Link http response header
        // if the container doesn't exist yet, so refetch the container
        // now that it has been created:
        await store.fetcher.load(chatContainer);
        // FIXME: check the Why value on this quad:
        const chatAclDoc = store.any(chatContainer, new external_$rdf_.NamedNode('http://www.iana.org/assignments/link-relations/acl'));
        if (!chatAclDoc) {
            throw new Error('Chat ACL doc not found!');
        }
        const aclBody = `
            @prefix acl: <http://www.w3.org/ns/auth/acl#>.
            <#owner>
            a acl:Authorization;
            acl:agent <${me.value}>;
            acl:accessTo <.>;
            acl:default <.>;
            acl:mode
                acl:Read, acl:Write, acl:Control.
            <#invitee>
            a acl:Authorization;
            acl:agent <${invitee.value}>;
            acl:accessTo <.>;
            acl:default <.>;
            acl:mode
                acl:Read, acl:Append.
            `;
        await store.fetcher.webOperation('PUT', chatAclDoc.value, {
            data: aclBody,
            contentType: 'text/turtle',
        });
    }
    async function addToPrivateTypeIndex(chatThing, me) {
        // Add to private type index
        const privateTypeIndex = store.any(me, ns.solid('privateTypeIndex'));
        if (!privateTypeIndex) {
            throw new Error('Private type index not found!');
        }
        await store.fetcher.load(privateTypeIndex);
        const reg = newThing(privateTypeIndex);
        const ins = [
            (0,external_$rdf_.st)(reg, ns.rdf('type'), ns.solid('TypeRegistration'), privateTypeIndex.doc()),
            (0,external_$rdf_.st)(reg, ns.solid('forClass'), ns.meeting('LongChat'), privateTypeIndex.doc()),
            (0,external_$rdf_.st)(reg, ns.solid('instance'), chatThing, privateTypeIndex.doc()),
        ];
        await new Promise((resolve, reject) => {
            store.updater.update([], ins, function (_uri, ok, errm) {
                if (!ok) {
                    reject(new Error(errm));
                }
                else {
                    resolve(null);
                }
            });
        });
    }
    async function findChat(invitee) {
        const me = await profileLogic.loadMe();
        const podRoot = await profileLogic.getPodRoot(me);
        const chatContainer = determineChatContainer(invitee, podRoot);
        let exists = true;
        try {
            await store.fetcher.load(new external_$rdf_.NamedNode(chatContainer.value + 'index.ttl#this'));
        }
        catch (e) {
            exists = false;
        }
        return { me, chatContainer, exists };
    }
    async function createChatThing(chatContainer, me) {
        const created = await mintNew({
            me,
            newBase: chatContainer.value,
        });
        return created.newInstance;
    }
    function mintNew(newPaneOptions) {
        const kb = store;
        const updater = kb.updater;
        if (newPaneOptions.me && !newPaneOptions.me.uri) {
            throw new Error('chat mintNew:  Invalid userid ' + newPaneOptions.me);
        }
        const newInstance = (newPaneOptions.newInstance =
            newPaneOptions.newInstance ||
                kb.sym(newPaneOptions.newBase + CHAT_LOCATION_IN_CONTAINER));
        const newChatDoc = newInstance.doc();
        kb.add(newInstance, ns.rdf('type'), ns.meeting('LongChat'), newChatDoc);
        kb.add(newInstance, ns.dc('title'), 'Chat channel', newChatDoc);
        kb.add(newInstance, ns.dc('created'), (0,external_$rdf_.term)(new Date(Date.now())), newChatDoc);
        if (newPaneOptions.me) {
            kb.add(newInstance, ns.dc('author'), newPaneOptions.me, newChatDoc);
        }
        return new Promise(function (resolve, reject) {
            updater === null || updater === void 0 ? void 0 : updater.put(newChatDoc, kb.statementsMatching(undefined, undefined, undefined, newChatDoc), 'text/turtle', function (uri2, ok, message) {
                if (ok) {
                    resolve({
                        ...newPaneOptions,
                        newInstance,
                    });
                }
                else {
                    reject(new Error('FAILED to save new chat channel at: ' + uri2 + ' : ' + message));
                }
            });
        });
    }
    /**
     * Find (and optionally create) an individual chat between the current user and the given invitee
     * @param invitee - The person to chat with
     * @param createIfMissing - Whether the chat should be created, if missing
     * @returns null if missing, or a node referring to an already existing chat, or the newly created chat
     */
    async function getChat(invitee, createIfMissing = true) {
        const { me, chatContainer, exists } = await findChat(invitee);
        if (exists) {
            return new external_$rdf_.NamedNode(chatContainer.value + CHAT_LOCATION_IN_CONTAINER);
        }
        if (createIfMissing) {
            const chatThing = await createChatThing(chatContainer, me);
            await sendInvite(invitee, chatThing);
            await setAcl(chatContainer, me, invitee);
            await addToPrivateTypeIndex(chatThing, me);
            return chatThing;
        }
        return null;
    }
    async function sendInvite(invitee, chatThing) {
        var _a;
        await store.fetcher.load(invitee.doc());
        const inviteeInbox = store.any(invitee, ns.ldp('inbox'), undefined, invitee.doc());
        if (!inviteeInbox) {
            throw new Error(`Invitee inbox not found! ${invitee.value}`);
        }
        const inviteBody = `
        <> a <http://www.w3.org/ns/pim/meeting#LongChatInvite> ;
        ${ns.rdf('seeAlso')} <${chatThing.value}> .
        `;
        const inviteResponse = await ((_a = store.fetcher) === null || _a === void 0 ? void 0 : _a.webOperation('POST', inviteeInbox.value, {
            data: inviteBody,
            contentType: 'text/turtle',
        }));
        const locationStr = inviteResponse === null || inviteResponse === void 0 ? void 0 : inviteResponse.headers.get('location');
        if (!locationStr) {
            throw new Error(`Invite sending returned a ${inviteResponse === null || inviteResponse === void 0 ? void 0 : inviteResponse.status}`);
        }
    }
    return {
        setAcl, addToPrivateTypeIndex, findChat, createChatThing, getChat, sendInvite, mintNew
    };
}

;// ./src/inbox/inboxLogic.ts

function createInboxLogic(store, profileLogic, utilityLogic, containerLogic, aclLogic) {
    async function createInboxFor(peerWebId, nick) {
        const myWebId = await profileLogic.loadMe();
        const podRoot = await profileLogic.getPodRoot(myWebId);
        const ourInbox = `${podRoot.value}p2p-inboxes/${encodeURIComponent(nick)}/`;
        await containerLogic.createContainer(ourInbox);
        // const aclDocUrl = await aclLogic.findAclDocUrl(ourInbox);
        await utilityLogic.setSinglePeerAccess({
            ownerWebId: myWebId.value,
            peerWebId,
            accessToModes: 'acl:Append',
            target: ourInbox
        });
        return ourInbox;
    }
    async function getNewMessages(user) {
        if (!user) {
            user = await profileLogic.loadMe();
        }
        const inbox = await profileLogic.getMainInbox(user);
        const urls = await containerLogic.getContainerMembers(inbox);
        return urls.filter(url => !containerLogic.isContainer(url));
    }
    async function markAsRead(url, date) {
        const downloaded = await store.fetcher._fetch(url);
        if (downloaded.status !== 200) {
            throw new Error(`Not OK! ${url}`);
        }
        const archiveUrl = getArchiveUrl(url, date);
        const options = {
            method: 'PUT',
            body: await downloaded.text(),
            headers: [
                ['Content-Type', downloaded.headers.get('Content-Type') || 'application/octet-stream']
            ]
        };
        const uploaded = await store.fetcher._fetch(archiveUrl, options);
        if (uploaded.status.toString()[0] === '2') {
            await store.fetcher._fetch(url, {
                method: 'DELETE'
            });
        }
    }
    return {
        createInboxFor,
        getNewMessages,
        markAsRead
    };
}

;// ./src/logic/CustomError.ts
class CustomError extends Error {
    constructor(message) {
        super(message);
        // see: typescriptlang.org/docs/handbook/release-notes/typescript-2-2.html
        Object.setPrototypeOf(this, new.target.prototype); // restore prototype chain
        this.name = new.target.name; // stack traces display correctly now
    }
}
class UnauthorizedError extends CustomError {
}
class CrossOriginForbiddenError extends CustomError {
}
class SameOriginForbiddenError extends CustomError {
}
class NotFoundError extends CustomError {
}
class NotEditableError extends CustomError {
}
class WebOperationError extends CustomError {
}
class FetchError extends CustomError {
    constructor(status, message) {
        super(message);
        this.status = status;
    }
}

;// ./src/profile/profileLogic.ts




function createProfileLogic(store, authn, utilityLogic) {
    const ns = ns_ns;
    /**
     * loads the preference without throwing errors - if it can create it it does so.
     * remark: it still throws error if it cannot load profile.
     * @param user
     * @returns undefined if preferenceFile cannot be returned or NamedNode if it can find it or create it
     */
    async function silencedLoadPreferences(user) {
        try {
            return await loadPreferences(user);
        }
        catch (err) {
            return undefined;
        }
    }
    /**
     * loads the preference without returning different errors if it cannot create or load it.
     * remark: it also throws error if it cannot load profile.
     * @param user
     * @returns undefined if preferenceFile cannot be an Error or NamedNode if it can find it or create it
     */
    async function loadPreferences(user) {
        await loadProfile(user);
        const possiblePreferencesFile = suggestPreferencesFile(user);
        let preferencesFile;
        try {
            preferencesFile = await utilityLogic.followOrCreateLink(user, ns.space('preferencesFile'), possiblePreferencesFile, user.doc());
        }
        catch (err) {
            const message = `User ${user} has no pointer in profile to preferences file.`;
            warn(message);
            // we are listing the possible errors
            if (err instanceof NotEditableError) {
                throw err;
            }
            if (err instanceof WebOperationError) {
                throw err;
            }
            if (err instanceof UnauthorizedError) {
                throw err;
            }
            if (err instanceof CrossOriginForbiddenError) {
                throw err;
            }
            if (err instanceof SameOriginForbiddenError) {
                throw err;
            }
            if (err instanceof FetchError) {
                throw err;
            }
            throw err;
        }
        try {
            await store.fetcher.load(preferencesFile);
        }
        catch (err) { // Maybe a permission problem or origin problem
            const msg = `Unable to load preference of user ${user}: ${err}`;
            warn(msg);
            if (err.response.status === 401) {
                throw new UnauthorizedError();
            }
            if (err.response.status === 403) {
                if (differentOrigin(preferencesFile)) {
                    throw new CrossOriginForbiddenError();
                }
                throw new SameOriginForbiddenError();
            }
            /*if (err.response.status === 404) {
                throw new NotFoundError();
            }*/
            throw new Error(msg);
        }
        return preferencesFile;
    }
    async function loadProfile(user) {
        if (!user) {
            throw new Error('loadProfile: no user given.');
        }
        try {
            await store.fetcher.load(user.doc());
        }
        catch (err) {
            throw new Error(`Unable to load profile of user ${user}: ${err}`);
        }
        return user.doc();
    }
    async function loadMe() {
        const me = authn.currentUser();
        if (me === null) {
            throw new Error('Current user not found! Not logged in?');
        }
        await store.fetcher.load(me.doc());
        return me;
    }
    function getPodRoot(user) {
        const podRoot = findStorage(user);
        if (!podRoot) {
            throw new Error('User pod root not found!');
        }
        return podRoot;
    }
    async function getMainInbox(user) {
        await store.fetcher.load(user);
        const mainInbox = store.any(user, ns.ldp('inbox'), undefined, user.doc());
        if (!mainInbox) {
            throw new Error('User main inbox not found!');
        }
        return mainInbox;
    }
    function findStorage(me) {
        return store.any(me, ns.space('storage'), undefined, me.doc());
    }
    return {
        loadMe,
        getPodRoot,
        getMainInbox,
        findStorage,
        loadPreferences,
        loadProfile,
        silencedLoadPreferences
    };
}

;// ./src/typeIndex/typeIndexLogic.ts




function createTypeIndexLogic(store, authn, profileLogic, utilityLogic) {
    const ns = ns_ns;
    function getRegistrations(instance, theClass) {
        return store
            .each(undefined, ns.solid('instance'), instance)
            .filter((r) => {
            return store.holds(r, ns.solid('forClass'), theClass);
        });
    }
    async function loadTypeIndexesFor(user) {
        if (!user)
            throw new Error('loadTypeIndexesFor: No user given');
        const profile = await profileLogic.loadProfile(user);
        const suggestion = suggestPublicTypeIndex(user);
        let publicTypeIndex;
        try {
            publicTypeIndex = await utilityLogic.followOrCreateLink(user, ns.solid('publicTypeIndex'), suggestion, profile);
        }
        catch (err) {
            const message = `User ${user} has no pointer in profile to publicTypeIndex file.`;
            warn(message);
        }
        const publicScopes = publicTypeIndex ? [{ label: 'public', index: publicTypeIndex, agent: user }] : [];
        let preferencesFile;
        try {
            preferencesFile = await profileLogic.silencedLoadPreferences(user);
        }
        catch (err) {
            preferencesFile = null;
        }
        let privateScopes;
        if (preferencesFile) { // watch out - can be in either as spec was not clear.  Legacy is profile.
            // If there is a legacy one linked from the profile, use that.
            // Otherwiae use or make one linked from Preferences
            const suggestedPrivateTypeIndex = suggestPrivateTypeIndex(preferencesFile);
            let privateTypeIndex;
            try {
                privateTypeIndex = store.any(user, ns.solid('privateTypeIndex'), undefined, profile) ||
                    await utilityLogic.followOrCreateLink(user, ns.solid('privateTypeIndex'), suggestedPrivateTypeIndex, preferencesFile);
            }
            catch (err) {
                const message = `User ${user} has no pointer in preference file to privateTypeIndex file.`;
                warn(message);
            }
            privateScopes = privateTypeIndex ? [{ label: 'private', index: privateTypeIndex, agent: user }] : [];
        }
        else {
            privateScopes = [];
        }
        const scopes = publicScopes.concat(privateScopes);
        if (scopes.length === 0)
            return scopes;
        const files = scopes.map(scope => scope.index);
        try {
            await store.fetcher.load(files);
        }
        catch (err) {
            warn('Problems loading type index: ', err);
        }
        return scopes;
    }
    async function loadCommunityTypeIndexes(user) {
        let preferencesFile;
        try {
            preferencesFile = await profileLogic.silencedLoadPreferences(user);
        }
        catch (err) {
            const message = `User ${user} has no pointer in profile to preferences file.`;
            warn(message);
        }
        if (preferencesFile) { // For now, pick up communities as simple links from the preferences file.
            const communities = store.each(user, ns.solid('community'), undefined, preferencesFile).concat(store.each(user, ns.solid('community'), undefined, user.doc()));
            let result = [];
            for (const org of communities) {
                result = result.concat(await loadTypeIndexesFor(org));
            }
            return result;
        }
        return []; // No communities
    }
    async function loadAllTypeIndexes(user) {
        return (await loadTypeIndexesFor(user)).concat((await loadCommunityTypeIndexes(user)).flat());
    }
    async function getScopedAppInstances(klass, user) {
        const scopes = await loadAllTypeIndexes(user);
        let scopedApps = [];
        for (const scope of scopes) {
            const scopedApps0 = await getScopedAppsFromIndex(scope, klass);
            scopedApps = scopedApps.concat(scopedApps0);
        }
        return scopedApps;
    }
    // This is the function signature which used to be in solid-ui/logic
    // Recommended to use getScopedAppInstances instead as it provides more information.
    //
    async function getAppInstances(klass) {
        const user = authn.currentUser();
        if (!user)
            throw new Error('getAppInstances: Must be logged in to find apps.');
        const scopedAppInstances = await getScopedAppInstances(klass, user);
        return scopedAppInstances.map(scoped => scoped.instance);
    }
    function suggestPublicTypeIndex(me) {
        var _a;
        return (0,external_$rdf_.sym)(((_a = me.doc().dir()) === null || _a === void 0 ? void 0 : _a.uri) + 'publicTypeIndex.ttl');
    }
    // Note this one is based off the pref file not the profile
    function suggestPrivateTypeIndex(preferencesFile) {
        var _a;
        return (0,external_$rdf_.sym)(((_a = preferencesFile.doc().dir()) === null || _a === void 0 ? void 0 : _a.uri) + 'privateTypeIndex.ttl');
    }
    /*
    * Register a new app in a type index
    * used in chat in bookmark.js (solid-ui)
    * Returns the registration object if successful else null
    */
    async function registerInTypeIndex(instance, index, theClass) {
        const registration = newThing(index);
        const ins = [
            // See https://github.com/solid/solid/blob/main/proposals/data-discovery.md
            (0,external_$rdf_.st)(registration, ns.rdf('type'), ns.solid('TypeRegistration'), index),
            (0,external_$rdf_.st)(registration, ns.solid('forClass'), theClass, index),
            (0,external_$rdf_.st)(registration, ns.solid('instance'), instance, index)
        ];
        try {
            await store.updater.update([], ins);
        }
        catch (err) {
            const msg = `Unable to register ${instance} in index ${index}: ${err}`;
            console.warn(msg);
            return null;
        }
        return registration;
    }
    async function deleteTypeIndexRegistration(item) {
        const reg = store.the(null, ns.solid('instance'), item.instance, item.scope.index);
        if (!reg)
            throw new Error(`deleteTypeIndexRegistration: No registration found for ${item.instance}`);
        const statements = store.statementsMatching(reg, null, null, item.scope.index);
        await store.updater.update(statements, []);
    }
    async function getScopedAppsFromIndex(scope, theClass) {
        const index = scope.index;
        const results = [];
        const registrations = store.statementsMatching(null, ns.solid('instance'), null, index)
            .concat(store.statementsMatching(null, ns.solid('instanceContainer'), null, index))
            .map(st => st.subject);
        for (const reg of registrations) {
            const klass = store.any(reg, ns.solid('forClass'), null, index);
            if (!theClass || klass.sameTerm(theClass)) {
                const instances = store.each(reg, ns.solid('instance'), null, index);
                for (const instance of instances) {
                    results.push({ instance, type: klass, scope });
                }
                const containers = store.each(reg, ns.solid('instanceContainer'), null, index);
                for (const instance of containers) {
                    await store.fetcher.load(instance);
                    results.push({ instance: (0,external_$rdf_.sym)(instance.value), type: klass, scope });
                }
            }
        }
        return results;
    }
    return {
        registerInTypeIndex,
        getRegistrations,
        loadTypeIndexesFor,
        loadCommunityTypeIndexes,
        loadAllTypeIndexes,
        getScopedAppInstances,
        getAppInstances,
        suggestPublicTypeIndex,
        suggestPrivateTypeIndex,
        deleteTypeIndexRegistration,
        getScopedAppsFromIndex
    };
}

;// ./src/util/containerLogic.ts

/**
 * Container-related class
 */
function createContainerLogic(store) {
    function getContainerElements(containerNode) {
        return store
            .statementsMatching(containerNode, (0,external_$rdf_.sym)('http://www.w3.org/ns/ldp#contains'), undefined)
            .map((st) => st.object);
    }
    function isContainer(url) {
        const nodeToString = url.value;
        return nodeToString.charAt(nodeToString.length - 1) === '/';
    }
    async function createContainer(url) {
        const stringToNode = (0,external_$rdf_.sym)(url);
        if (!isContainer(stringToNode)) {
            throw new Error(`Not a container URL ${url}`);
        }
        // Copied from https://github.com/solidos/solid-crud-tests/blob/v3.1.0/test/surface/create-container.test.ts#L56-L64
        const result = await store.fetcher._fetch(url, {
            method: 'PUT',
            headers: {
                'Content-Type': 'text/turtle',
                'If-None-Match': '*',
                Link: '<http://www.w3.org/ns/ldp#BasicContainer>; rel="type"', // See https://github.com/solidos/node-solid-server/issues/1465
            },
            body: ' ', // work around https://github.com/michielbdejong/community-server/issues/4#issuecomment-776222863
        });
        if (result.status.toString()[0] !== '2') {
            throw new Error(`Not OK: got ${result.status} response while creating container at ${url}`);
        }
    }
    async function getContainerMembers(containerUrl) {
        await store.fetcher.load(containerUrl);
        return getContainerElements(containerUrl);
    }
    return {
        isContainer,
        createContainer,
        getContainerElements,
        getContainerMembers
    };
}

;// ./src/util/utilityLogic.ts




function createUtilityLogic(store, aclLogic, containerLogic) {
    async function recursiveDelete(containerNode) {
        try {
            if (containerLogic.isContainer(containerNode)) {
                const aclDocUrl = await aclLogic.findAclDocUrl(containerNode);
                await store.fetcher._fetch(aclDocUrl, { method: 'DELETE' });
                const containerMembers = await containerLogic.getContainerMembers(containerNode);
                await Promise.all(containerMembers.map((url) => recursiveDelete(url)));
            }
            const nodeToStringHere = containerNode.value;
            return store.fetcher._fetch(nodeToStringHere, { method: 'DELETE' });
        }
        catch (e) {
            log(`Please manually remove ${containerNode.value} from your system.`, e);
        }
    }
    /**
     * Create a resource if it really does not exist
     * Be absolutely sure something does not exist before creating a new empty file
     * as otherwise existing could  be deleted.
     * @param doc {NamedNode} - The resource
     */
    async function loadOrCreateIfNotExists(doc) {
        let response;
        try {
            response = await store.fetcher.load(doc);
        }
        catch (err) {
            if (err.response.status === 404) {
                try {
                    await store.fetcher.webOperation('PUT', doc, { data: '', contentType: 'text/turtle' });
                }
                catch (err) {
                    const msg = 'createIfNotExists: PUT FAILED: ' + doc + ': ' + err;
                    throw new WebOperationError(msg);
                }
                await store.fetcher.load(doc);
            }
            else {
                if (err.response.status === 401) {
                    throw new UnauthorizedError();
                }
                if (err.response.status === 403) {
                    if (differentOrigin(doc)) {
                        throw new CrossOriginForbiddenError();
                    }
                    throw new SameOriginForbiddenError();
                }
                const msg = 'createIfNotExists doc load error NOT 404:  ' + doc + ': ' + err;
                throw new FetchError(err.status, err.message + msg);
            }
        }
        return response;
    }
    /* Follow link from this doc to another thing, or else make a new link
    **
    ** @returns existing object, or creates it if non existent
    */
    async function followOrCreateLink(subject, predicate, object, doc) {
        await store.fetcher.load(doc);
        const result = store.any(subject, predicate, null, doc);
        if (result)
            return result;
        if (!store.updater.editable(doc)) {
            const msg = `followOrCreateLink: cannot edit ${doc.value}`;
            warn(msg);
            throw new NotEditableError(msg);
        }
        try {
            await store.updater.update([], [(0,external_$rdf_.st)(subject, predicate, object, doc)]);
        }
        catch (err) {
            const msg = `followOrCreateLink: Error making link in ${doc} to ${object}: ${err}`;
            warn(msg);
            throw new WebOperationError(err);
        }
        try {
            await loadOrCreateIfNotExists(object);
            // store.fetcher.webOperation('PUT', object, { data: '', contentType: 'text/turtle'})
        }
        catch (err) {
            warn(`followOrCreateLink: Error loading or saving new linked document: ${object}: ${err}`);
            throw err;
        }
        return object;
    }
    // Copied from https://github.com/solidos/web-access-control-tests/blob/v3.0.0/test/surface/delete.test.ts#L5
    async function setSinglePeerAccess(options) {
        let str = [
            '@prefix acl: <http://www.w3.org/ns/auth/acl#>.',
            '',
            `<#alice> a acl:Authorization;\n  acl:agent <${options.ownerWebId}>;`,
            `  acl:accessTo <${options.target}>;`,
            `  acl:default <${options.target}>;`,
            '  acl:mode acl:Read, acl:Write, acl:Control.',
            ''
        ].join('\n');
        if (options.accessToModes) {
            str += [
                '<#bobAccessTo> a acl:Authorization;',
                `  acl:agent <${options.peerWebId}>;`,
                `  acl:accessTo <${options.target}>;`,
                `  acl:mode ${options.accessToModes}.`,
                ''
            ].join('\n');
        }
        if (options.defaultModes) {
            str += [
                '<#bobDefault> a acl:Authorization;',
                `  acl:agent <${options.peerWebId}>;`,
                `  acl:default <${options.target}>;`,
                `  acl:mode ${options.defaultModes}.`,
                ''
            ].join('\n');
        }
        const aclDocUrl = await aclLogic.findAclDocUrl((0,external_$rdf_.sym)(options.target));
        return store.fetcher._fetch(aclDocUrl, {
            method: 'PUT',
            body: str,
            headers: [
                ['Content-Type', 'text/turtle']
            ]
        });
    }
    async function createEmptyRdfDoc(doc, comment) {
        await store.fetcher.webOperation('PUT', doc.uri, {
            data: `# ${new Date()} ${comment}
  `,
            contentType: 'text/turtle',
        });
    }
    return {
        recursiveDelete,
        setSinglePeerAccess,
        createEmptyRdfDoc,
        followOrCreateLink,
        loadOrCreateIfNotExists
    };
}

;// ./src/logic/solidLogic.ts










/*
** It is important to distinquish `fetch`, a function provided by the browser
** and `Fetcher`, a helper object for the rdflib Store which turns it
** into a `ConnectedStore` or a `LiveStore`.  A Fetcher object is
** available at store.fetcher, and `fetch` function at `store.fetcher._fetch`,
*/
function createSolidLogic(specialFetch, session) {
    log('SolidLogic: Unique instance created.  There should only be one of these.');
    const store = external_$rdf_.graph();
    external_$rdf_.fetcher(store, { fetch: specialFetch.fetch }); // Attach a web I/O module, store.fetcher
    store.updater = new external_$rdf_.UpdateManager(store); // Add real-time live updates store.updater
    store.features = []; // disable automatic node merging on store load
    const authn = new SolidAuthnLogic(session);
    const acl = createAclLogic(store);
    const containerLogic = createContainerLogic(store);
    const utilityLogic = createUtilityLogic(store, acl, containerLogic);
    const profile = createProfileLogic(store, authn, utilityLogic);
    const chat = createChatLogic(store, profile);
    const inbox = createInboxLogic(store, profile, utilityLogic, containerLogic, acl);
    const typeIndex = createTypeIndexLogic(store, authn, profile, utilityLogic);
    log('SolidAuthnLogic initialized');
    function load(doc) {
        return store.fetcher.load(doc);
    }
    // @@@@ use the one in rdflib.js when it is available and delete this
    function updatePromise(del, ins = []) {
        return new Promise((resolve, reject) => {
            store.updater.update(del, ins, function (_uri, ok, errorBody) {
                if (!ok) {
                    reject(new Error(errorBody));
                }
                else {
                    resolve();
                }
            }); // callback
        }); // promise
    }
    function clearStore() {
        store.statements.slice().forEach(store.remove.bind(store));
    }
    return {
        store,
        authn,
        acl,
        inbox,
        chat,
        profile,
        typeIndex,
        load,
        updatePromise,
        clearStore
    };
}

;// ./src/logic/solidLogicSingleton.ts



const _fetch = async (url, requestInit) => {
    const omitCreds = requestInit && requestInit.credentials && requestInit.credentials == 'omit';
    if (authSession.info.webId && !omitCreds) { // see https://github.com/solidos/solidos/issues/114
        // In fact fetch should respect credentials omit itself
        return authSession.fetch(url, requestInit);
    }
    else {
        return window.fetch(url, requestInit);
    }
};
// Global singleton pattern to ensure unique store across library versions
const SINGLETON_SYMBOL = Symbol.for('solid-logic-singleton');
const globalTarget = (typeof window !== 'undefined' ? window : __webpack_require__.g);
function getOrCreateSingleton() {
    if (!globalTarget[SINGLETON_SYMBOL]) {
        log('SolidLogic: Creating new global singleton instance.');
        globalTarget[SINGLETON_SYMBOL] = createSolidLogic({ fetch: _fetch }, authSession);
        log('Unique quadstore initialized.');
    }
    else {
        log('SolidLogic: Using existing global singleton instance.');
    }
    return globalTarget[SINGLETON_SYMBOL];
}
//this const makes solidLogicSingleton global accessible in mashlib
const solidLogicSingleton = getOrCreateSingleton();


;// ./src/issuer/issuerLogic.ts
const DEFAULT_ISSUERS = [
    {
        name: 'Solid Community',
        uri: 'https://solidcommunity.net'
    },
    {
        name: 'Solid Web',
        uri: 'https://solidweb.org'
    },
    {
        name: 'Solid Web ME',
        uri: 'https://solidweb.me'
    },
    {
        name: 'Inrupt.com',
        uri: 'https://login.inrupt.com'
    }
];
/**
 * @returns - A list of suggested OIDC issuers
 */
function getSuggestedIssuers() {
    // Suggest a default list of OIDC issuers
    const issuers = [...DEFAULT_ISSUERS];
    // Suggest the current host if not already included
    const { host, origin } = new URL(location.href);
    const hosts = issuers.map(({ uri }) => new URL(uri).host);
    if (!hosts.includes(host) && !hosts.some(existing => isSubdomainOf(host, existing))) {
        issuers.unshift({ name: host, uri: origin });
    }
    return issuers;
}
function isSubdomainOf(subdomain, domain) {
    const dot = subdomain.length - domain.length - 1;
    return dot > 0 && subdomain[dot] === '.' && subdomain.endsWith(domain);
}

;// ./src/index.ts
// Make these variables directly accessible as it is what you need most of the time
// This also makes these variable globaly accesible in mashlib

const authn = solidLogicSingleton.authn;
const src_authSession = solidLogicSingleton.authn.authSession;
const store = solidLogicSingleton.store;







})();

/******/ 	return __webpack_exports__;
/******/ })()
;
});
//# sourceMappingURL=solid-logic.js.map