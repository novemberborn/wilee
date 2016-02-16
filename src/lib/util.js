import { inspect } from 'util'

import logUpdate from 'log-update'

export function dumpPayload (payload) {
  return inspect(payload, { depth: null })
}

export async function showPendingMessage (message, pending) {
  const maxDots = 3
  let count = 0
  const interval = setInterval(() => {
    logUpdate(`${message}${'.'.repeat(count++)}`)
    count %= maxDots + 1
  }, 500)

  try {
    return await pending
  } finally {
    clearInterval(interval)
    logUpdate.clear()
  }
}
