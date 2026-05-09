import std/[options, times]
import ./types, ./claims
import results

type
    ClaimValidationOptions* = object
        validateExp*:      bool
        validateNbf*:      bool
        clockSkewSeconds*: int64
        expectedIss*:      Option[string]
        expectedAud*:      Option[string]
        expectedSub*:      Option[string]


proc defaultValidationOptions*(): ClaimValidationOptions =
    ClaimValidationOptions(
        validateExp:      true,
        validateNbf:      true,
        clockSkewSeconds: 0,
        expectedIss:      none(string),
        expectedAud:      none(string),
        expectedSub:      none(string)
    )


proc validateClaims*(claims: JwtClaims, opts: ClaimValidationOptions): Result[void, JoseError] =
    let now = getTime().toUnix

    if opts.validateExp and claims.exp.isSome:
        if now > claims.exp.get + opts.clockSkewSeconds:
            return err(JoseError(kind: jeClaimValidation, msg: "Token has expired"))

    if opts.validateNbf and claims.nbf.isSome:
        if now < claims.nbf.get - opts.clockSkewSeconds:
            return err(JoseError(kind: jeClaimValidation, msg: "Token is not yet valid"))
    
    if opts.expectedIss.isSome:
        if claims.iss.isNone or claims.iss.get != opts.expectedIss.get:
            return err(JoseError(kind: jeClaimValidation, msg: "Issuer mismatch"))

    if opts.expectedAud.isSome:
        let expected = opts.expectedAud.get
        
        if claims.aud.isNone:
            return err(JoseError(kind: jeClaimValidation, msg: "Audience missing"))
        
        var found = false
        
        for a in claims.aud.get:
            if a == expected:
                found = true
                break

        if not found:
            return err(JoseError(kind: jeClaimValidation, msg: "Audience mismatch"))

    if opts.expectedSub.isSome:
        if claims.sub.isNone or claims.sub.get != opts.expectedSub.get:
            return err(JoseError(kind: jeClaimValidation, msg: "Subject mismatch"))
    
    ok()
