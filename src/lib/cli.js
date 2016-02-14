#! /usr/bin/env node
import { readFileSync } from 'fs'

import yargs from 'yargs'

import Account from './Account'
import * as commands from './commands'
import Server from './Server'

const argv = yargs
  .usage('Usage: $0 <command> [options]')
  .command('authorize', 'Authorize an identity')
  .demand(1)
  .check((argv) => {
    if (!commands.hasOwnProperty(argv._[0])) {
      throw new Error('Command required.')
    }
    return true
  })
  .argv

const account = new Account(readFileSync('account', 'ascii'), readFileSync('account.pub', 'ascii'))
const staging = new Server('https://acme-staging.api.letsencrypt.org/directory', account)

commands[argv._[0]](account, staging).catch((err) => {
  console.error(err && err.stack || err)
  process.exit(1)
})
