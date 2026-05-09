import unittest, std/json, std/options
import results
import jose/claims
import jose/types

suite "claims parsing":
    test "parse full standard claims":
        let j = %* {
            "iss": "https://example.com",
            "sub": "user-42",
            "aud": "api-server",
            "exp": 9999999999,
            "nbf": 1000000000,
            "iat": 1000000001,
            "jti": "unique-token-id"
        }
        
        let res = parseClaims(j)
        check res.isOk
        
        let c = res.value
        check c.iss == some("https://example.com")
        check c.sub == some("user-42")
        check c.aud == some(@["api-server"])
        check c.exp == some(9999999999'i64)
        check c.nbf == some(1000000000'i64)
        check c.iat == some(1000000001'i64)
        check c.jti == some("unique-token-id")

    test "parse minimal claims (only sub)":
        let j = %* {"sub": "user-1"}
        let res = parseClaims(j)
        
        check res.isOk
        
        let c = res.value
        check c.sub == some("user-1")
        check c.iss.isNone
        check c.exp.isNone

    test "aud as array":
        let j = %* {"aud": ["api1", "api2"]}
        let res = parseClaims(j)
        check res.isOk
        check res.value.aud == some(@["api1", "api2"])

    test "aud as single string becomes singleton seq":
        let j = %* {"aud": "my-api"}
        let res = parseClaims(j)
        
        check res.isOk
        check res.value.aud == some(@["my-api"])

    test "custom claims are stored in extra":
        
        let j = %* {"sub": "u1", "role": "admin", "level": 5}
        let res = parseClaims(j)
        
        check res.isOk
        
        let c = res.value
        
        check c.extra["role"].getStr == "admin"
        check c.extra["level"].getInt == 5

    test "non-object JSON is rejected":
        check parseClaims(%"a string").isErr
        check parseClaims(%42).isErr
        check parseClaims(%[1, 2, 3]).isErr

    test "wrong types for standard claims are rejected":
        check parseClaims(%* {"iss": 42}).isErr
        check parseClaims(%* {"exp": "not-a-number"}).isErr
        check parseClaims(%* {"aud": 99}).isErr

    test "toJsonNode round-trips claims":
        let j = %* {"iss": "ex.com", "sub": "u1", "exp": 9000000000, "role": "admin"}
        let res = parseClaims(j)
        
        check res.isOk
        
        let roundtripped = toJsonNode(res.value)
        
        check roundtripped["iss"].getStr == "ex.com"
        check roundtripped["sub"].getStr == "u1"
        check roundtripped["exp"].getBiggestInt == 9000000000'i64
        check roundtripped["role"].getStr == "admin"

