import unittest, std/strutils
import jose/base64url

# see https://datatracker.ietf.org/doc/html/rfc4648#section-10

suite "base64url":
    test "RFC 4648 Sec. 10 encode vectors":
        check encode("") == ""
        check encode("f") == "Zg"
        check encode("fo") == "Zm8"
        check encode("foo") == "Zm9v"
        check encode("foob") == "Zm9vYg"
        check encode("fooba") == "Zm9vYmE"
        check encode("foobar") == "Zm9vYmFy"

    test "URL-safe characters (no + or /)":
        let encoded = encode("\xfb\xff\xfe")
        
        for c in encoded:
            check c notin {'+', '/'}

    test "no padding characters":
        for len in 1..10:
            let s = "a".repeat(len)
            check '=' notin encode(s)

    test "decode RFC 4648 Sec. 10 vectors":
        check decode("") == ""
        check decode("Zg") == "f"
        check decode("Zm8") == "fo"
        check decode("Zm9v") == "foo"
        check decode("Zm9vYg") == "foob"
        check decode("Zm9vYmE") == "fooba"
        check decode("Zm9vYmFy") == "foobar"

    test "decode URL-safe characters":
        check decode("Y_c-") == decode("Y/c+".replace('/', '_').replace('+', '-'))

    test "round-trip invariant":
        for s in ["", "a", "ab", "abc", "abcd", "Hello, World!", "\x00\xff\xfe\xfd"]:
            check decode(encode(s)) == s

    test "decodeToBytes round-trip":
        let original = @[byte(0), 1, 2, 128, 255]
        let encoded = encode(original)
        
        check decodeToBytes(encoded) == original

