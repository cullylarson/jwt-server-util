# jwt-server-util

> Utility library for serving JWTs.

## Usage

If you choose to store your configuration information in a JSON file, there is a sample in `test/files/config.json`. This file assumes you are supporting multiple keys, using the first key to issue and any key verify (this allows you to add a new key before your old one expires and still support JWTs issued using the old key, until it expires).

### Required information

In order to issue a JWT, you'll need the following information:

- Public key.
- Private key.
- Serial number. Must be an integer, 20 bytes or less, hex encoded. Use `npm run generate-cert-serial-number` to generate one.
- validNotBefore. Don't consider the issuing key to be valid before this date (c.f. [Certificate Properties](https://docs.microsoft.com/en-us/windows/desktop/seccrypto/certificate-properties)). Should be a date that can be passed to the Date() constructor (e.g. "2019-05-23T00:00:00").
- validNotAfter. Don't consider the issuing keys to be valid after this date (c.f. [Certificate Properties](https://docs.microsoft.com/en-us/windows/desktop/seccrypto/certificate-properties)). Should be a date that can be passed to the Date() constructor (e.g. "2019-05-23T00:00:00").
- Expires In. How long you want the JWT to last (in seconds).
- Issuer. A value that identifies who issued the JWT (c.f. [RFC 7519](https://tools.ietf.org/html/rfc7519#section-4.1.1)). Also used as the Common Name when signing the certificate used to issue and verify the JWTs. However, since it is used entirely interally, it does not need to be a URL.
- Audience. One or more recipients for the JWT (c.f. [RFC 7519](https://tools.ietf.org/html/rfc7519#section-4.1.3)).
- Claim Namespace. The namespace used for custom claims.

None of these values should be stored in version control.

### Public/Private Keys

In order to sign JWTs, you'll need a public/private key pair. These should be generated using RS256, with at least a 2048 bit key size. You can generate them in Linux like this:

```
# Generate a private key
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
# Derive the public key from the private key
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

If you want to store your keys in a JSON file (e.g. a config file), note that JSON doesn't support newline characters. You'll need to replace them with `\n`. Here's a command to do that.

```
cat public_key.pem | sed 's/$/\\n/' | tr -d '\n'
cat private_key.pem | sed 's/$/\\n/' | tr -d '\n'
```

### Issue a JWT

```
npm install --save jwt-server-util
```

```js
import {promisify} from 'util'
import {getCertAndKeys} from 'jwt-server-util'
import {sign} from 'jsonwebtoken'
import {pki} from 'node-forge'

const signP = promisify(sign)

const signJwt = (issuer, audience, claimsNamespace, kid, expiresIn, privateKey) => {
    const payload = {
        // these are all custom claims. they can be whatever you want.
        [claimsNamespace]: {
            account: {
                name: 'Human Person',
                email: 'human@example.com',
            },
        },
    }

    const options = {
        algorithm: 'RS256',
        keyid: kid,
        issuer,
        audience,
        expiresIn,
    }

    return signP(payload, pki.privateKeyToPem(privateKey), options)
})

(async () => {
    // assuming config data is stored in a configuration file of some kind. though it could come from environment variables or some other source.
    const config = await readConfigFile('/path/to/config.json')

    // use the first key to issue the JWT (assumes the first key is the newest)
    const key = config.keys[0]

    const certAndKeys = getCertAndKeys(config.issuer, key.publicKeyPem, key.privateKeyPem, key.serialNumber, key.validNotBefore, key.validNotAfter)

    const jwt = await signJwt(config.issuer, config.audience, config.claimsNamespace, config.expiresIn, certAndKeys.cert.kid, certAndKeys.pair.priv)
})()
```

### Verify a JWT (Express)

This is an Express middleware that uses [express-jwt](https://github.com/auth0/express-jwt) to verify a JWT. Any routes added after this middleware will require a valid JWT.

```js
import jwt from 'express-jwt'

const CheckJwt = (jwksUri, audience, issuer) => {
    return jwt({
        // Dynamically provide a signing key based on the kid in the header and the signing keys provided by the JWKS endpoint.
        secret: expressJwtSecret({
            cache: true,
            rateLimit: true,
            jwksRequestsPerMinute: 5,
            jwksUri,
        }),
        audience,
        issuer,
        algorithms: ['RS256'],
        requestProperty: 'jwtDecoded', // the request object will get the decoded jwt at this key
    })
}

// the audience and issuer need to match values from your config. these should not be hard-coded and should not be committed to version control.
const checkJwt = CheckJwt("https://localhost/.well-known/jwks.json", "https://alt.example.com", "https://example.com")

app.use(checkJwt)
```

### JWKS Endpoint (Express)

A sample JWKS endpoint for verifying JWTs:

```js
import {getCertAndKeys} from 'jwt-server-util'

// allows for using multiple certs (i.e. you add a new cert to issue JWTs, but you want to keep the old one around until it expires so you can continue to support JWTs issued with it)
const JwksAction = (certs) => {
    const keys = certs.map(cert => ({
        alg: 'RSA256',
        kty: 'RSA',
        use: 'sig',
        x5c: [cert.certDer],
        e: String(cert.exponent),
        n: cert.modulus.toString('base64'),
        kid: cert.kid,
        x5t: cert.thumbprintEncoded,
    }))

    return (req, res) => res.json({keys})
}

// assuming config data is stored in a configuration file of some kind. though it could come from environment variables or some other source.
const config = readConfigFile('/path/to/config.json')

const certs = config.keys
    .map(key => getCertAndKeys(config.issuer, key.publicKeyPem, key.privateKeyPem, key.serialNumber, key.validNotBefore, key.validNotAfter))
    .map(x => x.cert)

app.get('/.well-known/jwks.json', JwksAction(certs))
```
