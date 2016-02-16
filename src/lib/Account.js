import { createHash } from 'crypto'

import { createPrivateKey as parsePrivateKey } from 'ursa'
import jwt from 'jsonwebtoken'
import { pem2jwk } from 'pem-jwk'
import { urlencode as base64url } from 'sixtyfour'

function getPublicKey (privateKey) {
  const parsed = parsePrivateKey(privateKey)
  return parsed.toPublicPem()
}

function getJwk (key) {
  const { e, kty, n } = pem2jwk(key)
  // Return in alphabetical order so the result can be used when computing
  // thumbprints.
  return { e, kty, n }
}

function getThumbprint (jwk) {
  const json = JSON.stringify(jwk)
  const octets = new Buffer(json, 'utf8')
  const hash = createHash('sha256').update(octets).digest()
  return base64url(hash)
}

export default class Account {
  constructor (privateKey) {
    const publicKey = getPublicKey(privateKey)
    this.jwk = getJwk(publicKey)
    this.thumbprint = getThumbprint(this.jwk)

    this.sign = (payload, nonce) => {
      return jwt.sign(payload, privateKey, {
        algorithm: 'RS256',
        headers: {
          jwk: this.jwk,
          nonce
        }
      })
    }
  }
}
