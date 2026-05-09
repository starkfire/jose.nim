import std/[json, strutils, options]
import nimcrypto/utils
import ./[types, base64url, jwa]
import results

proc splitToken*(token: string): Result[RawToken, JoseError] =
    let parts = token.split('.')

    if parts.len != 3:
        return err(JoseError(kind: jeInvalidFormat, msg: "A JWT must have exactly 3 parts separated by '.'"))

    ok(
        RawToken(
            headerB64: parts[0],
            payloadB64: parts[1],
            signatureB64: parts[2]
        )
    )

proc parseHeader*(headerB64: string): Result[JwtHeader, JoseError] =
    var headerJson: string

    try:
        headerJson = base64url.decode(headerB64)
    except CatchableError:
        return err(JoseError(kind: jeInvalidFormat, msg: "Header is not valid base64url"))

    var node: JsonNode

    try:
        node = parseJson(headerJson)
    except CatchableError:
        return err(JoseError(kind: jeInvalidFormat, msg: "Header is not valid JSON"))

    if node.kind != JObject:
        return err(JoseError(kind: jeInvalidFormat, msg: "Header must be a JSON object"))

    let algNode = node.getOrDefault("alg")

    if algNode.isNil or algNode.kind != JString:
        return err(JoseError(kind: jeInvalidFormat, msg: "Missing or invalid 'alg' in header"))

    let algOpt = parseJwaAlgorithm(algNode.getStr)

    if algOpt.isNone:
        return err(JoseError(kind: jeInvalidAlgorithm, msg: "Unsupported algorithm: " & algNode.getStr))

    var header = JwtHeader(alg: algOpt.get, typ: "JWT")

    let typNode = node.getOrDefault("typ")

    if not typNode.isNil and typNode.kind == JString:
        header.typ = typNode.getStr

    let kidNode = node.getOrDefault("kid")

    if not kidNode.isNil and kidNode.kind == JString:
        header.kid = some(kidNode.getStr)

    ok(header)


proc compactSign*(header: JwtHeader, payloadJson: JsonNode, key: openArray[byte]): Result[string, JoseError] =
    if not isHmacAlgorithm(header.alg):
        return err(JoseError(kind: jeInvalidAlgorithm, msg: "compactSign requires an HS* algorithm"))
    
    let headerObj = newJObject()
    headerObj["alg"] = %($header.alg)
    headerObj["typ"] = %header.typ
    
    if header.kid.isSome:
        headerObj["kid"] = %header.kid.get

    let headerB64  = base64url.encode($headerObj)
    let payloadB64 = base64url.encode($payloadJson)
    let sigInput   = headerB64 & "." & payloadB64
    let sig        = hmacSign(header.alg, key, sigInput)

    ok(sigInput & "." & base64url.encode(sig))


proc compactVerify*(token: string, key: openArray[byte]): Result[RawToken, JoseError] =
    let rawRes = splitToken(token)
    
    if rawRes.isErr: return err(rawRes.error)
    
    let raw = rawRes.value

    let headerRes = parseHeader(raw.headerB64)
    
    if headerRes.isErr: return err(headerRes.error)
    
    let header = headerRes.value

    if not isHmacAlgorithm(header.alg):
        return err(JoseError(kind: jeInvalidAlgorithm, msg: "compactVerify requires an HS* algorithm"))

    let sigInput    = raw.headerB64 & "." & raw.payloadB64
    let expected    = hmacSign(header.alg, key, sigInput)
    var actual      : seq[byte]

    try:
        actual = base64url.decodeToBytes(raw.signatureB64)
    except CatchableError:
        return err(JoseError(kind: jeInvalidFormat, msg: "Signature is not valid base64url"))

    if not equalMemFull(expected, actual):
        return err(JoseError(kind: jeInvalidSignature, msg: "Signature verification failed"))

    ok(raw)
