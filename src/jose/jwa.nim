import ./types
import nimcrypto/[hmac, sha2]

proc isHmacAlgorithm*(alg: JwaAlgorithm): bool =
    alg in {HS256, HS384, HS512}


proc hmacSign*(alg: JwaAlgorithm, key: openArray[byte], data: string): seq[byte] =
    case alg
    of HS256: result = @(sha256.hmac(key, data).data)
    of HS384: result = @(sha384.hmac(key, data).data)
    of HS512: result = @(sha512.hmac(key, data).data)
    else:
        raise newException(ValueError, "Invalid HMAC algorithm: " & $alg)

