import std/options

type
    JwaAlgorithm* = enum
        HS256, HS384, HS512,
        RS256, RS384, RS512,
        ES256, ES384, ES512,
        PS256, PS384, PS512

    JwtHeader* = object
        alg*: JwaAlgorithm
        typ*: string
        kid*: Option[string]
        cty*: Option[string]

    RawToken* = object
        headerB64*: string
        payloadB64*: string
        signatureB64*: string

    JoseErrorKind* = enum
        jeInvalidFormat
        jeInvalidAlgorithm
        jeInvalidSignature
        jeClaimValidation
        jeKeyError
        jeUnsupportedTarget

    JoseError* = object
        kind*: JoseErrorKind
        msg*: string


proc parseJwaAlgorithm*(s: string): Option[JwaAlgorithm] =
    case s
    of "HS256": some(HS256)
    of "HS384": some(HS384)
    of "HS512": some(HS512)
    of "RS256": some(RS256)
    of "RS384": some(RS384)
    of "RS512": some(RS512)
    of "ES256": some(ES256)
    of "ES384": some(ES384)
    of "ES512": some(ES512)
    of "PS256": some(PS256)
    of "PS384": some(PS384)
    of "PS512": some(PS512)
    else: none(JwaAlgorithm)

