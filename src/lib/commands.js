import { createHash } from 'crypto'
import { readFileSync } from 'fs'
import { inspect } from 'util'

import { urlencode as base64url } from 'sixtyfour'

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

export async function authorize (account, server) {
  console.log('Retrieving directory')
  logResult(await server.directory)

  console.log('Creating or retrieving registration')
  const registration = await server.register('mark@novemberborn.net')
  logResult(registration)

  if (registration.payload.agreement !== registration.links['terms-of-service']) {
    console.log('Accepting terms of service')
    logResult(await server.acceptTermsOfService(registration.links.self, registration.links['terms-of-service']))
  }

  const domainName = 'novemberborn.net'
  console.log(`Authorizing for ${domainName}`)
  const authz = await server.authorizeIdentifier(domainName)
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
    logResult(await server.meetChallenge(uri, type, keyAuthorization))

    console.log('Waiting for status to change')
    logResult(await server.pollPendingAuthorization(authzUrl))
  }
}

export async function issue (account, server) {
  const csr = base64url(readFileSync('csr.der'))

  console.log('Retrieving directory')
  logResult(await server.directory)

  console.log('Issuing certificate')
  const certificate = await server.issue(csr)
  logResult(certificate)
}

export async function retrieve (account, server, uri) {
  console.log('Retrieving certificate from', uri)
  logResult(await server.getCert(uri))
}
