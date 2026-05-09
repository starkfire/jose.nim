# Package

version       = "0.1.0"
author        = "starkfire"
description   = "JOSE (JSON Object Signing and Encryption) library for Nim"
license       = "MIT"
srcDir        = "src"


# Dependencies

requires "nim >= 2.2.6"
requires "nimcrypto >= 0.6.2"
requires "results >= 0.5.0"

task sharedlib, "Build shared library for Node.js FFI":
    exec "nim c --app:lib --noMain --mm:arc -d:release --path:src -o:libjose.so src/jose_ffi.nim"

