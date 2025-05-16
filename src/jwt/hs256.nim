import std/strformat
import nimcrypto/[hmac, sha2]
import ./utils

proc hs256*(key, message: string): string =
    var ctx: HMAC[sha256]
    ctx.init(key)
    ctx.update(message)
    $ctx.finish()

proc signHs256*(header, payload: string, secret: string): string =
    let signingInput = fmt"{header}.{payload}"
    let signature = hs256(secret, signingInput)
    base64UrlEncode(signature)
