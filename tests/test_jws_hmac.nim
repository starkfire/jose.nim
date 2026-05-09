import unittest, std/strutils, std/json
import results
import jose/base64url
import jose/jws
import jose/types

suite "JWS HMAC":
    # Fixed HS256 known-good vector for this header, payload, and key.
    const rfc7515A1Key   = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
    const rfc7515A1Token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" &
    ".eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" &
    ".lliDzOlRAdGUCfCHCPx_uisb6ZfZ1LRQa0OJLeYTTpY"

    test "verify known HS256 token":
        let key = decodeToBytes(rfc7515A1Key)
        let res = compactVerify(rfc7515A1Token, key)
        check res.isOk

    test "wrong key is rejected":
        let wrongKey = decodeToBytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        let res = compactVerify(rfc7515A1Token, wrongKey)
        check res.isErr
        check res.error.kind == jeInvalidSignature

    test "tampered signature is rejected":
        var tampered = rfc7515A1Token
        let lastDot = tampered.rfind('.')
        tampered[lastDot + 1] = if tampered[lastDot + 1] == 'd': 'e' else: 'd'
        let key = decodeToBytes(rfc7515A1Key)
        let res = compactVerify(tampered, key)
        check res.isErr
        check res.error.kind == jeInvalidSignature

    test "HS256 sign/verify round-trip":
        let key = cast[seq[byte]]("supersecretkey-must-be-long-enough!")
        let header = JwtHeader(alg: HS256, typ: "JWT")
        let payload = %* {"sub": "user1", "iat": 1000000}
        let signRes = compactSign(header, payload, key)
        check signRes.isOk
        check compactVerify(signRes.value, key).isOk

    test "HS384 sign/verify round-trip":
        let key = cast[seq[byte]]("supersecretkey-must-be-long-enough!")
        let header = JwtHeader(alg: HS384, typ: "JWT")
        let payload = %* {"sub": "user1"}
        let signRes = compactSign(header, payload, key)
        check signRes.isOk
        check compactVerify(signRes.value, key).isOk

    test "HS512 sign/verify round-trip":
        let key = cast[seq[byte]]("supersecretkey-must-be-long-enough!")
        let header = JwtHeader(alg: HS512, typ: "JWT")
        let payload = %* {"sub": "user1"}
        let signRes = compactSign(header, payload, key)
        check signRes.isOk
        check compactVerify(signRes.value, key).isOk

    test "wrong key rejects token":
        let key = cast[seq[byte]]("supersecretkey-must-be-long-enough!")
        let header = JwtHeader(alg: HS256, typ: "JWT")
        let payload = %* {"sub": "user1"}
        let signRes = compactSign(header, payload, key)
        check signRes.isOk
        check compactVerify(signRes.value, key).isOk
        let otherKey = cast[seq[byte]]("different-secret-key-long-enough!!")
        check compactVerify(signRes.value, otherKey).isErr
