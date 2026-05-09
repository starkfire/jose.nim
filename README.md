# jose.nim

[JOSE](https://datatracker.ietf.org/wg/jose/about/) (JSON Object Signing and Encryption) library in Nim.


## API Reference

### `jose/jwt`

High-Level API.

- `sign(claims: JsonNode, key: openArray[byte], alg: JwaAlgorithm = HS256): Result[string, JoseError]`
    - signs a `JsonNode` payload; returns a compact JWS string
    - uses `HS256` as the default signing algorithm
- `verify(token, key, opts): Result[JwtClaims, JoseError]`
    - verifies the signature and validates claims from an input JWS string; returns the claims (`JwtClaims`)
- `decode(token: string): Result[(JwtHeader, JwtClaims), JoseError]`
    - decodes a given JWS string and returns its decoded headers and claims (no signature check)

### `jose/jws`

Low-Level Compact Serialization.

- `compactSign(header: JwtHeader, payload: JsonNode, key: openArray[byte]): Result[string, JoseError]`
    - signs a `JsonNode` payload with an input `JoseHeader`
- `compactVerify(token: string, key: openArray[byte]): Result[RawToken, JoseError]`
    - verifies a token and returns the raw token parts
- `splitToken(token: string): Result[RawToken, JoseError]`
    - splits a given compact token into its Base64URL parts
- `parseHeader(headerB64: string): Result[JwtHeader, JoseError]`
    - decodes and parses a JWS header from its Base64URL encoding

### `jose/claims`

For parsing claims.

- `parseClaims(node: JsonNode): Result[JwtClaims, JoseError]`
    - parse a `JsonNode` into a `JwtClaims` object
- `toJsonNode(claims: JwtClaims): JsonNode`
    - serializes a `JwtClaims` back to `JsonNode`

### `jose/validation`

For validating claims.

- `validateClaims(claims: JwtClaims, opts: ClaimValidationOptions): Result[void, JoseError]`
    - runs all enabled checks against the input `JwtClaims`
- `defaultValidationOptions(): ClaimValidationOptions`
    - returns the default options for validating claims

### `jose/base64url`

Primitives for Base64URL encoding.

- `encode(data: openArray[byte] | string): string | string`
    - encode a given `string` or `openArray[byte]` (no padding)
- `decode(str: string): string`
    - decode a given Base64URL string
- `decodeToBytes(str: string): seq[byte]`
    - decodes a given Base64URL string; returns a sequence of bytes

## Usage in Node.js

An example on using this in Node.js can be found at `nodejs/` within this project. `src/jose_ffi.nim` provides an FFI layer that you can use to call the Nim procedures inside Node.

Build the shared library (`libjose.so`):

```sh
nimble sharedlib
# or
nim c --app:lib --noMain --mm:arc -d:release --path:src -o:libjose.so src/jose_ffi.nim
```

Use a Node FFI module (e.g. [Koffi](https://koffi.dev/)) to load the shared library:

```js
const koffi = require("koffi")
const path = require("path")

const lib = koffi.load(path.resolve(__dirname, "..", "libjose.so"))

const jose_init   = lib.func("void jose_init()")
const jose_sign   = lib.func("const char *jose_sign(const char *claimsJson, const char *key, const char *alg)")
const jose_verify = lib.func("const char *jose_verify(const char *token, const char *key)")
const jose_decode = lib.func("const char *jose_decode(const char *token)")

jose_init() 
```

The FFI layer encodes results with an `ERR:` prefix. Thus, you'll need to write a JS function for handling those errors:

```js
function check(str) {
    if (str.startsWith("ERR:")) throw new Error(str.slice(4))
    return str
}
```

You may then write reusable JS functions that call the Nim procedures (along with your error handler.)

```js 
// index.js
function sign(claims, key, alg = "HS256") {
    return check(jose_sign(JSON.stringify(claims), key, alg))
}

module.exports = { sign }
```
```js
// example.js
const jose = require("./index")

const secret = "my-secret-key"

const token = jose.sign(
    {
        sub: "1234567890",
        name: "John Doe",
        iat: Math.floor(Date.now() / 1000)
    },
    secret,
    "HS256"
)

console.log("Token:", token)
```

