import std/base64, std/strutils

proc base64UrlEncode*(s: string): string =
    result = encode(s, true)
    result = result.strip(trailing = true, chars = {'='})
    return result

proc base64UrlDecode*(s: string): string =
    result = decode(s)
    return result

