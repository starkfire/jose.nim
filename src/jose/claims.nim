import std/[json, options]
import ./[types]
import results


type
    JwtClaims* = object
        iss*: Option[string]
        sub*: Option[string]
        aud*: Option[seq[string]]
        exp*: Option[int64]
        nbf*: Option[int64]
        iat*: Option[int64]
        jti*: Option[string]
        extra*: JsonNode


proc parseClaims*(node: JsonNode): Result[JwtClaims, JoseError] =
    if node.kind != JObject:
        return err(JoseError(kind: jeInvalidFormat, msg: "Claims must be a JSON object"))

    var claims: JwtClaims
    claims.extra = newJObject()

    for key, val in node.pairs:
        case key
        of "iss":
            if val.kind != JString:
                return err(JoseError(kind: jeInvalidFormat, msg: "iss must be a string"))
            claims.iss = some(val.getStr)
        of "sub":
            if val.kind != JString:
                return err(JoseError(kind: jeInvalidFormat, msg: "sub must be a string"))
            claims.sub = some(val.getStr)
        of "aud":
            case val.kind
            of JString:
                claims.aud = some(@[val.getStr])
            of JArray:
                var audiences: seq[string]
                
                for item in val:
                    if item.kind != JString:
                        return err(JoseError(kind: jeInvalidFormat, msg: "aud array items must be strings"))
                    
                    audiences.add(item.getStr)

                claims.aud = some(audiences)
            else:
                return err(JoseError(kind: jeInvalidFormat, msg: "aud must be a string or array"))
        of "exp":
            if val.kind != JInt:
                return err(JoseError(kind: jeInvalidFormat, msg: "exp must be an integer"))
            claims.exp = some(val.getBiggestInt.int64)
        of "nbf":
            if val.kind != JInt:
                return err(JoseError(kind: jeInvalidFormat, msg: "nbf must be an integer"))
            claims.nbf = some(val.getBiggestInt.int64)
        of "iat":
            if val.kind != JInt:
                return err(JoseError(kind: jeInvalidFormat, msg: "iat must be an integer"))
            claims.iat = some(val.getBiggestInt.int64)
        of "jti":
            if val.kind != JString:
                return err(JoseError(kind: jeInvalidFormat, msg: "jti must be a string"))
            claims.jti = some(val.getStr)
        else:
            claims.extra[key] = val

    ok(claims)


proc toJsonNode*(claims: JwtClaims): JsonNode =
    result = newJObject()

    if claims.iss.isSome: result["iss"] = %claims.iss.get
    if claims.sub.isSome: result["sub"] = %claims.sub.get
    if claims.aud.isSome:
        let a = claims.aud.get
        
        if a.len == 1:
            result["aud"] = %a[0]
        else:
            result["aud"] = %a
    if claims.exp.isSome: result["exp"] = %claims.exp.get
    if claims.nbf.isSome: result["nbf"] = %claims.nbf.get
    if claims.iat.isSome: result["iat"] = %claims.iat.get
    if claims.jti.isSome: result["jti"] = %claims.jti.get
    
    for key, val in claims.extra.pairs:
        result[key] = val

