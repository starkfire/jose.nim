import unittest, std/json, std/times, std/options
import results
import jose/claims
import jose/validation
import jose/types

proc makeClaims(j: JsonNode): JwtClaims =
    let res = parseClaims(j)
    doAssert res.isOk, res.error.msg
    res.value

suite "claim validation":
    let now = getTime().toUnix

    test "valid token with all claims passes":
        let c = makeClaims(%* {
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "aud": "my-api",
            "exp": now + 3600,
            "nbf": now - 10
        })
        var opts = defaultValidationOptions()
        opts.expectedIss = some("https://auth.example.com")
        opts.expectedAud = some("my-api")
        check validateClaims(c, opts).isOk

    test "expired token is rejected":
        let c = makeClaims(%* {"exp": now - 1})
        check validateClaims(c, defaultValidationOptions()).isErr
        check validateClaims(c, defaultValidationOptions()).error.kind == jeClaimValidation

    test "not-yet-valid token is rejected":
        let c = makeClaims(%* {"nbf": now + 3600})
        check validateClaims(c, defaultValidationOptions()).isErr

    test "clock skew allows slightly expired token":
        let c = makeClaims(%* {"exp": now - 29})
        var opts = defaultValidationOptions()
        opts.clockSkewSeconds = 30
        check validateClaims(c, opts).isOk

    test "clock skew does not allow very expired token":
        let c = makeClaims(%* {"exp": now - 31})
        var opts = defaultValidationOptions()
        opts.clockSkewSeconds = 30
        check validateClaims(c, opts).isErr

    test "clock skew allows slightly future nbf":
        let c = makeClaims(%* {"nbf": now + 29})
        var opts = defaultValidationOptions()
        opts.clockSkewSeconds = 30
        check validateClaims(c, opts).isOk

    test "wrong issuer is rejected":
        let c = makeClaims(%* {"iss": "https://attacker.com"})
        var opts = defaultValidationOptions()
        opts.expectedIss = some("https://auth.example.com")
        check validateClaims(c, opts).isErr
        check validateClaims(c, opts).error.kind == jeClaimValidation

    test "missing issuer when expected is rejected":
        let c = makeClaims(%* {"sub": "u1"})
        var opts = defaultValidationOptions()
        opts.expectedIss = some("https://auth.example.com")
        check validateClaims(c, opts).isErr

    test "audience mismatch is rejected":
        let c = makeClaims(%* {"aud": "wrong-api"})
        var opts = defaultValidationOptions()
        opts.expectedAud = some("my-api")
        check validateClaims(c, opts).isErr

    test "audience match succeeds (multi-audience token)":
        let c = makeClaims(%* {"aud": ["api1", "my-api", "api3"]})
        var opts = defaultValidationOptions()
        opts.expectedAud = some("my-api")
        check validateClaims(c, opts).isOk

    test "validateExp=false skips expiration check":
        let c = makeClaims(%* {"exp": now - 9999})
        var opts = defaultValidationOptions()
        opts.validateExp = false
        check validateClaims(c, opts).isOk

    test "validateNbf=false skips nbf check":
        let c = makeClaims(%* {"nbf": now + 9999})
        var opts = defaultValidationOptions()
        opts.validateNbf = false
        check validateClaims(c, opts).isOk

    test "absent exp with validateExp=true passes":
        let c = makeClaims(%* {"sub": "u1"})
        check validateClaims(c, defaultValidationOptions()).isOk

    test "subject mismatch is rejected":
        let c = makeClaims(%* {"sub": "user-2"})
        var opts = defaultValidationOptions()
        opts.expectedSub = some("user-1")
        check validateClaims(c, opts).isErr

