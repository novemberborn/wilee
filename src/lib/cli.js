#! /usr/bin/env node
import { readFileSync } from 'fs'
import { inspect } from 'util'

import yargs from 'yargs'

import Account from './Account'
import * as commands from './commands'
import Server from './Server'

var argv = yargs
  .usage('Usage: $0 <command> [options]')
  .help('help')
  .command('authorize', 'Authorize an identity')
  .command('issue', 'Issue a certificate')
  .command('retrieve', 'Retrieve a certificate by URI', (yargs) => {
    return yargs
      .usage('Usage: $0 retrieve <uri>')
      .help('help')
      .demand(1)
      .argv
  })
  .demand(1)
  .argv

if (!commands.hasOwnProperty(argv._[0])) {
  console.error(yargs.help())
  process.exit(1)
}

const account = new Account(readFileSync('account', 'ascii'), readFileSync('account.pub', 'ascii'))
const staging = new Server('https://acme-staging.api.letsencrypt.org/directory', account)

commands[argv._[0]](account, staging, ...argv._.slice(1)).catch((err) => {
  console.error(err && err.stack || err)
  const keys = Object.keys(err)
  for (const k of keys) {
    console.error(`${k}: ${inspect(err[k], { depth: null })}`)
  }
  process.exit(1)
})
