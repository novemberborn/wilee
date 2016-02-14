import { createHash } from 'crypto'

import jwt from 'jsonwebtoken'
import { pem2jwk } from 'pem-jwk'
import { urlencode as base64url } from 'sixtyfour'

function getJwk (key) {
  const { e, kty, n } = pem2jwk(key)
  return { e, kty, n }
}

function getThumbprint (jwk) {
  const json = JSON.stringify(jwk)
  const octets = new Buffer(json, 'utf8')
  const hash = createHash('sha256').update(octets).digest()
  return base64url(hash)
}

export default class Account {
  constructor (privateKey, publicKey) {
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
