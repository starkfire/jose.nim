"use strict"

const jose = require("./index")

const secret = "my-secret-key"

// sign
const token = jose.sign(
    { 
        sub: "1234567890", 
        name: "John Doe", 
        iat: Math.floor(Date.now() / 1000) 
    },
    secret,
    "HS256"
)

console.log("Token:", token)

// verify
const claims = jose.verify(token, secret)

console.log("Verified claims:", claims)

// decode (no signature check)
const { header, claims: decoded } = jose.decode(token)

console.log("Header:", header)
console.log("Claims:", decoded)

// tamper detection
try {
    jose.verify(token + "tampered", secret)
} catch (e) {
    console.log("Tamper detected:", e.message)
}
