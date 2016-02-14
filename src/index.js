import { createHash } from 'crypto'
import { readFileSync } from 'fs'
import { inspect } from 'util'

import jwt from 'jsonwebtoken'
import { pem2jwk } from 'pem-jwk'
import { urlencode as base64url } from 'sixtyfour'

import Server from './lib/Server'

function logResult (result) {
  console.log(inspect(result, { depth: null }))
  console.log('\n')
}

const publicJwk = (function () {
  const publicKey = readFileSync('account.pub', 'ascii')
  const { e, kty, n } = pem2jwk(publicKey)
  return { e, kty, n }
})()

const thumbprint = (function () {
  const json = JSON.stringify(publicJwk)
  const octets = new Buffer(json, 'utf8')
  const hash = createHash('sha256').update(octets).digest()
  return base64url(hash)
})()

const sign = (function () {
  const privateKey = readFileSync('account', 'ascii')

  return function sign (payload, nonce) {
    return jwt.sign(payload, privateKey, {
      algorithm: 'RS256',
      headers: {
        jwk: publicJwk,
        nonce
      }
    })
  }
})()

const mayContinue = () => {
  return new Promise((resolve) => {
    process.stdin.resume()
    process.stdin.once('data', () => {
      process.stdin.pause()
      resolve()
    })
  })
}

const staging = new Server('https://acme-staging.api.letsencrypt.org/directory', sign)

;(async function () {
  console.log('Retrieving directory')
  logResult(await staging.directory)

  console.log('Creating or retrieving registration')
  const registration = await staging.register('mark@novemberborn.net')
  logResult(registration)

  if (registration.payload.agreement !== registration.links['terms-of-service']) {
    console.log('Accepting terms of service')
    logResult(await staging.acceptTermsOfService(registration.links.self, registration.links['terms-of-service']))
  }

  const domainName = 'novemberborn.net'
  console.log(`Authorizing for ${domainName}`)
  const authz = await staging.authorizeIdentifier(domainName)
  logResult(authz)

  const {
    links: { self: authzUrl },
    payload: {
      status: authzStatus,
      challenges: authzChallenges
    }
  } = authz

  if (authzStatus === 'pending') {
    const { token, type, uri } = authzChallenges.find((c) => c.type === 'dns-01')

    const keyAuthorization = `${token}.${thumbprint}`
    const txtRecord = base64url(createHash('sha256').update(keyAuthorization, 'ascii').digest())
    console.log(`Please create a TXT record:

\t_acme-challenge.${domainName}
\t${txtRecord}

Press ENTER to continue.`)

    await mayContinue()

    console.log('Meeting DNS challenge')
    logResult(await staging.meetChallenge(uri, type, keyAuthorization))

    console.log('Waiting for status to change')
    logResult(await staging.pollPendingAuthorization(authzUrl))
  }
})().catch((err) => {
  console.error(err && err.stack || err)
  process.exit(1)
})
