import { readFileSync, writeFileSync } from 'fs'

import { urlencode as base64url } from 'sixtyfour'

import { inspect } from '../lib/util'

export default async function newCert (account, client, csrFile, outFile, notAfter, notBefore) {
  const csr = base64url(readFileSync(csrFile))

  const { statusCode, body, links: { self: certUri } } = await client.newCert(csr, notAfter, notBefore)
  if (statusCode !== 200 && statusCode !== 201) {
    console.error(`Could not obtain the certificate.

Server returned ${inspect(body)}`)
    return 1
  }

  console.log(`Certificate issued! Download it at ${certUri}`)

  if (outFile) {
    writeFileSync(outFile, body)
    console.log(`Written certificate to ${outFile}`)
  }
}
