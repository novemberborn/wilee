import { createHash } from 'crypto'
import { resolveTxt } from 'dns'

import { urlencode as base64url } from 'sixtyfour'

import { inspect, showPendingMessage } from '../lib/util'

export default async function newAuthz (account, server, domainName) {
  const {
    statusCode,
    links: { self: authzUri },
    payload,
    payload: {
      status,
      challenges
    }
  } = await server.authorizeIdentifier(domainName)

  if (statusCode !== 201) {
    console.error(`Could not create an authorization for ${domainName}

Server returned ${inspect(payload)}`)
    return 1
  }

  if (status === 'pending') {
    const dnsChallenge = challenges.find((c) => c.type === 'dns-01')
    if (!dnsChallenge) {
      const received = challenges.map((c) => `'${c.type}'`).join(', ')
      console.error(`Server did not issue a supported challenge.
Received ${received} but only 'dns-01' is supported.`)
      return 1
    }

    const [ok, err] = await meetDnsChallenge({
      account,
      server,
      domainName,
      authzUri,
      dnsChallenge
    })
    if (!ok) {
      console.error(`Failed to meet DNS challenge for ${domainName}

Server returned ${inspect(err)}`)
      return 1
    }
  }

  console.log(`Created authorization at ${authzUri}`)
}

async function meetDnsChallenge ({
  account: { thumbprint },
  server,
  domainName,
  authzUri,
  dnsChallenge: { token, type, uri }
}) {
  const hostname = `_acme-challenge.${domainName}`
  const keyAuthorization = `${token}.${thumbprint}`
  const record = base64url(createHash('sha256').update(keyAuthorization, 'ascii').digest())
  console.log(`Please create a TXT record:

\t${hostname}
\t${record}
`)

  await showPendingMessage('Checking DNS records', pollDns(hostname, record))

  {
    const { statusCode, payload } = await server.meetChallenge(uri, type, keyAuthorization)
    if (statusCode !== 202) {
      return [false, payload]
    }
  }

  {
    const verifying = server.pollPendingAuthorization(authzUri)
    const { statusCode, payload } = await showPendingMessage('Waiting for ACME server to verify DNS records', verifying)
    if (statusCode !== 200) {
      return [false, payload]
    }
  }

  return [true, null]
}

async function pollDns (hostname, expected) {
  await new Promise((resolve) => setTimeout(resolve, 5000))

  const exists = await new Promise((resolve, reject) => {
    resolveTxt(hostname, (err, records) => {
      if (err) {
        reject(err)
      } else {
        resolve(records.some((chunks) => chunks.indexOf(expected) !== -1))
      }
    })
  })

  return exists || pollDns(hostname, expected)
}
