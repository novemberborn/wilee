import { readFileSync, writeFileSync } from 'fs'

import { urlencode as base64url } from 'sixtyfour'

import { inspect } from '../lib/util'

export default async function newCert (account, server, csrFile, outFile, notAfter, notBefore) {
  const csr = base64url(readFileSync(csrFile))

  const { statusCode, payload, links: { self: certUri } } = await server.issue(csr, notAfter, notBefore)
  if (statusCode !== 200 && statusCode !== 201) {
    console.error(`Could not obtain the certificate.

Server returned ${inspect(payload)}`)
    return 1
  }

  console.log(`Certificate issued! Download it at ${certUri}`)

  if (outFile) {
    writeFileSync(outFile, payload, 'base64')
    console.log(`Written certificate to ${outFile}`)
  }
}
