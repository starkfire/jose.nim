import std/strutils

proc hexToBytes*(str: string): seq[byte] =
    let clean = str.replace(" ", "").replace("\n", "").toLowerAscii
    assert clean.len mod 2 == 0, "hex string must have even length"

    result = newSeq[byte](clean.len div 2)
    for i in 0 ..< result.len:
        result[i] = byte(parseHexInt(clean[i * 2 .. i * 2 + 1]))

