import { createHash } from 'crypto'
import { resolveTxt } from 'dns'

import { urlencode as base64url } from 'sixtyfour'

import { inspect, showPendingMessage } from '../lib/util'

export default async function newAuthz (account, client, domainName) {
  const {
    statusCode,
    links: { self: authzUri },
    body,
    body: {
      status,
      challenges
    }
  } = await client.newAuthz(domainName)

  if (statusCode !== 201) {
    console.error(`Could not create an authorization for ${domainName}

Server returned ${inspect(body)}`)
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
      client,
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
  client,
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
    const { statusCode, body } = await client.challenge(uri, type, keyAuthorization)
    if (statusCode !== 202) {
      return [false, body]
    }
  }

  {
    const verifying = client.pollPendingAuthz(authzUri)
    const { statusCode, body } = await showPendingMessage('Waiting for ACME server to verify DNS records', verifying)
    if (statusCode !== 200) {
      return [false, body]
    }
  }

  return [true, null]
}

async function pollDns (hostname, expected) {
  await new Promise((resolve) => setTimeout(resolve, 5000))

  const exists = await new Promise((resolve, reject) => {
    resolveTxt(hostname, (err, records) => {
      if (err) {
        if (err.code === 'ENOTFOUND') {
          resolve(false)
        } else {
          reject(err)
        }
      } else {
        resolve(records.some((chunks) => chunks.indexOf(expected) !== -1))
      }
    })
  })

  return exists || pollDns(hostname, expected)
}
