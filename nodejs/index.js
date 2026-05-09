"use strict"

const koffi = require("koffi")
const path = require("path")

const lib = koffi.load(path.resolve(__dirname, "..", "libjose.so"))

const jose_init   = lib.func("void jose_init()")
const jose_sign   = lib.func("const char *jose_sign(const char *claimsJson, const char *key, const char *alg)")
const jose_verify = lib.func("const char *jose_verify(const char *token, const char *key)")
const jose_decode = lib.func("const char *jose_decode(const char *token)")

jose_init()

function check(str) {
    if (str.startsWith("ERR:")) throw new Error(str.slice(4))
    return str
}

/**
 * Sign a JWT.
 * 
 * @param {object} claims - Claims payload (will be JSON-serialized)
 * @param {string} key    - HMAC secret
 * @param {string} alg    - Algorithm: HS256 (default), HS384, or HS512
 * 
 * @returns {string} Compact JWT string
 */
function sign(claims, key, alg = "HS256") {
    return check(jose_sign(JSON.stringify(claims), key, alg))
}

/**
 * Verify a JWT and return its claims.
 * Validates signature and, if present, exp/nbf.
 * 
 * @param {string} token - Compact JWT string
 * @param {string} key   - HMAC secret
 * 
 * @returns {object} Parsed claims
 */
function verify(token, key) {
    return JSON.parse(check(jose_verify(token, key)))
}

/**
 * Decode a JWT without verifying the signature.
 * 
 * @param {string} token - Compact JWT string
 * 
 * @returns {{ header: object, claims: object }}
 */
function decode(token) {
    return JSON.parse(check(jose_decode(token)))
}

module.exports = { sign, verify, decode }

