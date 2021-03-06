import readline from 'readline'

import { inspect } from '../lib/util'

export default async function newReg (account, client, email) {
  const {
    statusCode,
    links: { self: regUri, 'terms-of-service': tosUri },
    body,
    body: { agreement }
  } = await client.newReg(email)

  if (statusCode !== 200 && statusCode !== 201 && statusCode !== 202) {
    console.error(`Could not register account.

Server returned ${inspect(body)}`)
    return 1
  }

  if (agreement !== tosUri) {
    await requireTosAgreement(tosUri)
    const { statusCode, body } = await client.updateRegAgreement(regUri, tosUri)
    if (statusCode !== 200 && statusCode !== 202) {
      console.error(`Failed to agree to the Terms of Service.

Server returned ${inspect(body)}`)
      return 1
    }
  }

  console.log(`Account registered at ${regUri}`)
}

async function requireTosAgreement (uri) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
  const prompt = () => {
    return new Promise((resolve) => {
      rl.question(`
You need to agree to the Terms of Service, which you can read at:

${uri}

Enter 'agree' if you agree to the Terms of Service: `, (answer) => resolve(answer === 'agree'))
    }).then((agreed) => agreed || prompt())
  }

  await prompt()
  rl.close()
  console.log('')
}
