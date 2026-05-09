import std/base64

proc encode*(data: openArray[byte]): string =
    result = base64.encode(data, safe = true)
    while result.len > 0 and result[^1] == '=':
        result.setLen(result.len - 1)

proc encode*(str: string): string =
    if str.len == 0:
        return ""
    
    encode(str.toOpenArrayByte(0, str.high))


proc decode*(str: string): string =
    var padded = str

    for i in 0 ..< padded.len:
        case padded[i]
        of '-': padded[i] = '+'
        of '_': padded[i] = '/'
        else: discard
    
    case padded.len mod 4
    of 2: padded.add("==")
    of 3: padded.add("=")
    else: discard

    result = base64.decode(padded)


proc decodeToBytes*(str: string): seq[byte] =
    let decoded = decode(str)
    result = newSeq[byte](decoded.len)

    for i in 0 ..< decoded.len:
        result[i] = decoded[i].byte

