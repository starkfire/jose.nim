import unittest, std/json, std/times, std/options, std/strutils
import results
import jose/jwt as jwt
import jose/base64url as b64url
import jose/types
import jose/validation

proc toBytes(s: string): seq[byte] =
    result = newSeq[byte](s.len)

    for i, ch in s:
        result[i] = ch.byte

let testKey = toBytes("supersecretkey-must-be-long-enough!")

# alg:none header — base64url({"alg":"none"}).base64url({}).""
const noneToken = "eyJhbGciOiJub25lIn0.e30."

suite "JWT high-level API":
    test "decode rejects alg:none token":
        let res = jwt.decode(noneToken)
        check res.isErr
        check res.error.kind == jeInvalidAlgorithm

    test "decode rejects structurally invalid token":
        check jwt.decode("not.a.valid.token.here").isErr
        check jwt.decode("onlytwoparts").isErr
        check jwt.decode("bad!!.payload.sig").isErr

    test "decode works without key (JS-safe path)":
        let signed = sign(%* {"sub": "u1", "iss": "ex.com"}, testKey)
        check signed.isOk
        
        let decoded = jwt.decode(signed.value)
        check decoded.isOk
        
        let (header, claims) = decoded.value
        check header.alg == HS256
        check claims.sub == some("u1")
        check claims.iss == some("ex.com")

    test "sign produces a 3-part dot-separated token":
        let res = sign(%* {"sub": "u1"}, testKey)
        check res.isOk
        
        let parts = res.value.split('.')
        check parts.len == 3

    test "verify succeeds with correct key":
        let signed = sign(%* {"sub": "user-1", "exp": getTime().toUnix + 3600}, testKey)
        check signed.isOk
        
        let res = verify(signed.value, testKey)
        check res.isOk
        check res.value.sub == some("user-1")

    test "verify fails with wrong key":
        let signed = sign(%* {"sub": "u1", "exp": getTime().toUnix + 3600}, testKey)
        check signed.isOk
        
        let wrongKey = toBytes("completely-different-secret-key!!")
        let res = verify(signed.value, wrongKey)
        check res.isErr
        check res.error.kind == jeInvalidSignature

    test "tampered payload is rejected":
        let signed = sign(%* {"sub": "u1", "exp": getTime().toUnix + 3600}, testKey)
        check signed.isOk
        
        let token = signed.value
        let parts = token.split('.')
        let fakePayload = b64url.encode($ %* {"sub": "admin", "exp": getTime().toUnix + 3600})
        let tampered = parts[0] & "." & fakePayload & "." & parts[2]
        let res = verify(tampered, testKey)
        check res.isErr
        check res.error.kind == jeInvalidSignature

    test "claims survive round-trip":
        let now = getTime().toUnix
        let signed = sign(%* {
            "sub":  "user-99",
            "iss":  "https://auth.example.com",
            "exp":  now + 7200,
            "role": "editor"
        }, testKey)
        check signed.isOk
        
        var opts = defaultValidationOptions()
        opts.expectedIss = some("https://auth.example.com")
        let res = verify(signed.value, testKey, opts)
        check res.isOk
        
        let c = res.value
        check c.sub == some("user-99")
        check c.iss == some("https://auth.example.com")
        check c.extra["role"].getStr == "editor"

    test "expired token is rejected by verify":
        let signed = sign(%* {"sub": "u1", "exp": getTime().toUnix - 1}, testKey)
        check signed.isOk
        
        let res = verify(signed.value, testKey)
        check res.isErr
        check res.error.kind == jeClaimValidation

    test "sign with HS384 and verify":
        let signed = sign(%* {"sub": "u1", "exp": getTime().toUnix + 3600}, testKey, alg = HS384)
        check signed.isOk
        
        let res = verify(signed.value, testKey)
        check res.isOk

    test "sign with HS512 and verify":
        let signed = sign(%* {"sub": "u1", "exp": getTime().toUnix + 3600}, testKey, alg = HS512)
        check signed.isOk
        
        let res = verify(signed.value, testKey)
        check res.isOk
