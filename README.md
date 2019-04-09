### Signing vs Encryption

A token is simply a JSON object that is signed by its author. this tells you exactly two things about the data:

* The author of the token was in the possession of the signing secret
* The data has not been modified since it was signed

It's important to know that JWT does not provide encryption, which means anyone who has access to the token can read its contents. If you need to protect (encrypt) the data, there is a companion spec, `JWE`, that provides this functionality. JWE is currently outside the scope of this library.

### Choosing a Signing Method

There are several signing methods available, and you should probably take the time to learn about the various options before choosing one.  The principal design decision is most likely going to be symmetric vs asymmetric.

Symmetric signing methods, such as HSA, use only a single secret. This is probably the simplest signing method to use since any `[]byte` can be used as a valid secret. They are also slightly computationally faster to use, though this rarely is enough to matter. Symmetric signing methods work the best when both producers and consumers of tokens are trusted, or even the same system. Since the same secret is used to both sign and validate tokens, you can't easily distribute the key for validation.

Asymmetric signing methods, such as RSA, use different keys for signing and verifying tokens. This makes it possible to produce tokens with a private key, and allow any consumer to access the public key for verification.

### Signing Methods and Key Types

Each signing method expects a different object type for its signing keys. See the package documentation for details. Here are the most common ones:

* The [HMAC signing method](https://godoc.org/github.com/yacen/alg#SigningMethodHMAC) (`HS256`,`HS384`,`HS512`) expect `[]byte` values for signing and validation
* The [RSA signing method](https://godoc.org/github.com/yacen/alg#SigningMethodRSA) (`RS256`,`RS384`,`RS512`) expect `*rsa.PrivateKey` for signing and `*rsa.PublicKey` for validation
* The [ECDSA signing method](https://godoc.org/github.com/yacen/alg#SigningMethodECDSA) (`ES256`,`ES384`,`ES512`) expect `*ecdsa.PrivateKey` for signing and `*ecdsa.PublicKey` for validation