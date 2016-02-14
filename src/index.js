import { createHash } from 'crypto'
import { readFileSync } from 'fs'
import { inspect } from 'util'

import { urlencode as base64url } from 'sixtyfour'

import Account from './lib/Account'
import Server from './lib/Server'

function logResult (result) {
  console.log(inspect(result, { depth: null }))
  console.log('\n')
}

const mayContinue = () => {
  return new Promise((resolve) => {
    process.stdin.resume()
    process.stdin.once('data', () => {
      process.stdin.pause()
      resolve()
    })
  })
}

const account = new Account(readFileSync('account', 'ascii'), readFileSync('account.pub', 'ascii'))
const staging = new Server('https://acme-staging.api.letsencrypt.org/directory', account)

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

    const keyAuthorization = `${token}.${account.thumbprint}`
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
