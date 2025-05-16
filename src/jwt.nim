import std/[json, strformat, times]
import jwt/[hs256, utils]

proc encodeJwt(payload: JsonNode, secret: string): string =
    let header = %*{
        "alg": "HS256",
        "typ": "JWT"
    }

    let encodedHeader = base64UrlEncode($header)
    let encodedPayload = base64UrlEncode($payload)
    let signature = signHs256(encodedHeader, encodedPayload, secret)

    fmt"{encodedHeader}.{encodedPayload}.{signature}"

let payload = %*{
    "sub": "1234567",
    "name": "Jane Doe",
    "iat": getTime().toUnix()
}

let secret = "my_secret"
let token = encodeJwt(payload, secret)

echo token
