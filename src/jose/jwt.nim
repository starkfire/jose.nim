import std/[json, options]
import ./[types, base64url, claims, validation, jws]
import results

proc decode*(token: string): Result[(JwtHeader, JwtClaims), JoseError] =
    let rawRes = splitToken(token)

    if rawRes.isErr: return err(rawRes.error)

    let raw = rawRes.value
    let headerRes = parseHeader(raw.headerB64)
    
    if headerRes.isErr: return err(headerRes.error)
    
    var payloadJson: string

    try:
        payloadJson = base64url.decode(raw.payloadB64)
    except CatchableError:
        return err(JoseError(kind: jeInvalidFormat, msg: "Payload is not valid base64url"))

    var payloadNode: JsonNode
    
    try:
        payloadNode = parseJson(payloadJson)
    except CatchableError:
        return err(JoseError(kind: jeInvalidFormat, msg: "Payload is not valid JSON"))
    
    let claimsRes = parseClaims(payloadNode)
    if claimsRes.isErr: return err(claimsRes.error)
    
    ok((headerRes.value, claimsRes.value))


proc sign*(claims: JsonNode, key: openArray[byte], alg: JwaAlgorithm = HS256): Result[string, JoseError] =
    let header = JwtHeader(alg: alg, typ: "JWT", kid: none(string), cty: none(string))
    compactSign(header, claims, key)

proc verify*(
    token: string,
    key:   openArray[byte],
    opts:  ClaimValidationOptions = defaultValidationOptions()
): Result[JwtClaims, JoseError] =
    let rawRes = compactVerify(token, key)
    
    if rawRes.isErr: return err(rawRes.error)
    let raw = rawRes.value
    var payloadJson: string

    try:
        payloadJson = base64url.decode(raw.payloadB64)
    except CatchableError:
        return err(JoseError(kind: jeInvalidFormat, msg: "Payload is not valid base64url"))

    var payloadNode: JsonNode

    try:
        payloadNode = parseJson(payloadJson)
    except CatchableError:
        return err(JoseError(kind: jeInvalidFormat, msg: "Payload is not valid JSON"))

    let claimsRes = parseClaims(payloadNode)

    if claimsRes.isErr: return err(claimsRes.error)
    
    let validRes = validateClaims(claimsRes.value, opts)
    
    if validRes.isErr: return err(validRes.error)
    
    ok(claimsRes.value)
