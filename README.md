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

