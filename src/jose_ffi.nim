import std/[json, options]
import jose
import jose/jwt as jwtMod
import results

proc NimMain() {.importc.}
var tls_result {.threadvar.}: string

proc setResult(str: string): cstring =
    tls_result = str
    result = cstring(tls_result)

proc toBytes(str: string): seq[byte] =
    result = newSeq[byte](str.len)
    for i in 0 ..< str.len:
        result[i] = byte(str[i])

proc jose_init() {.exportc, dynlib.} =
    NimMain()

proc jose_sign(claimsJson: cstring, key: cstring, alg: cstring): cstring {.exportc, dynlib.} =
    if claimsJson.isNil or key.isNil or alg.isNil:
        return setResult("ERR:nil argument")

    let algOpt = parseJwaAlgorithm($alg)

    if algOpt.isNone:
        return setResult("ERR:Unknown algorithm: " & $alg)

    var node: JsonNode

    try:
        node = parseJson($claimsJson)
    except CatchableError as e:
        return setResult("ERR:Invalid JSON: " & e.msg)

    let keyBytes = toBytes($key)
    let res = sign(node, keyBytes, algOpt.get)

    if res.isErr:
        return setResult("ERR:" & res.error.msg)

    setResult(res.value)

proc jose_verify(token: cstring, key: cstring): cstring {.exportc, dynlib.} =
    if token.isNil or key.isNil:
        return setResult("ERR:nil argument")

    let keyBytes = toBytes($key)
    let res = verify($token, keyBytes)

    if res.isErr:
        return setResult("ERR:" & res.error.msg)

    setResult($toJsonNode(res.value))

proc jose_decode(token: cstring): cstring {.exportc, dynlib.} =
    if token.isNil:
        return setResult("ERR:nil argument")

    let res = jwtMod.decode($token)

    if res.isErr:
        return setResult("ERR:" & res.error.msg)

    let (header, jwtClaims) = res.value
    
    let output = %*{
        "header": {"alg": $header.alg, "typ": header.typ},
        "claims": toJsonNode(jwtClaims)
    }
    
    setResult($output)

