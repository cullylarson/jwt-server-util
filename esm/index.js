import base64url from 'base64url'
import {createHash} from 'crypto'
import forge from 'node-forge'
import NodeRSA from 'node-rsa'

const isObject = x => x !== null && typeof x === 'object'

export const getModulusExponent = publicKey => {
    const nodeRsa = new NodeRSA()
    nodeRsa.importKey(forge.pki.publicKeyToPem(publicKey))

    const {n: modulus, e: exponent} = nodeRsa.exportKey('components-public')

    return {
        modulus,
        exponent,
    }
}

export const getCertificatePem = (publicKey, privateKey, certSerialNumber, jwksOrigin, validNotBefore, validNotAfter) => {
    validNotBefore = isObject(validNotBefore) ? validNotBefore : new Date(validNotBefore)
    validNotAfter = isObject(validNotAfter) ? validNotAfter : new Date(validNotAfter)

    const attrs = [
        {
            name: 'commonName',
            value: `${jwksOrigin}`,
        },
    ]

    const cert = forge.pki.createCertificate()
    cert.publicKey = publicKey
    cert.serialNumber = certSerialNumber
    cert.validity.notBefore = validNotBefore
    cert.validity.notAfter = validNotAfter
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1)
    cert.setSubject(attrs)
    cert.sign(privateKey)

    return forge.pki.certificateToPem(cert)
}

export const getCertificateDer = certPem => {
    return forge.util.encode64(
        forge.asn1
            .toDer(forge.pki.certificateToAsn1(forge.pki.certificateFromPem(certPem)))
            .getBytes(),
    )
}

export const getCertThumbprint = certDer => {
    const derBinaryStr = Buffer.from(certDer).toString('binary')

    const shasum = createHash('sha1')
    shasum.update(derBinaryStr)

    return shasum.digest('base64')
}

export const getCertThumbprintEncoded = certDer => base64url.encode(getCertThumbprint(certDer))

export const getCertAndKeys = (issuer, publicKeyPem, privateKeyPem, certSerialNumber, validNotBefore, validNotAfter) => {
    const publicKey = forge.pki.publicKeyFromPem(publicKeyPem)
    const privateKey = forge.pki.privateKeyFromPem(privateKeyPem)

    const {modulus, exponent} = getModulusExponent(publicKey)
    const certPem = getCertificatePem(publicKey, privateKey, certSerialNumber, issuer, validNotBefore, validNotAfter)
    const certDer = getCertificateDer(certPem)
    const thumbprintEncoded = getCertThumbprintEncoded(certDer)

    return {
        pair: {
            pub: publicKey,
            priv: privateKey,
        },
        cert: {
            modulus,
            exponent,
            certPem,
            certDer,
            thumbprintEncoded,
            kid: thumbprintEncoded,
        },
    }
}
