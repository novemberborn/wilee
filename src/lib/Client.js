import https from 'https'
import { parse as parseUri } from 'url'

import getStream from 'get-stream'
import { utc } from 'moment'
import parseLinkHeader from 'parse-link-header'
import { parse as parseContentType } from 'content-type'

export default class Client {
  constructor (account, directoryUri) {
    this._account = account
    this._directoryUri = directoryUri

    this._nonces = []
    this._knownEndpoints = new Map()
  }

  async _getNonce () {
    if (this._nonces.length) {
      return Promise.resolve(this._nonces.shift())
    }

    const [nonce] = await request('HEAD', this._directoryUri)
    return nonce
  }

  _captureNonce (nonce) {
    if (nonce) {
      this._nonces.push(nonce)
    }
  }

  async _discoverEndpoint (resource) {
    if (this._knownEndpoints.has(resource)) {
      return Promise.resolve(this._knownEndpoints.get(resource))
    }

    const [nonce, { body, statusCode }] = await request('GET', this._directoryUri)
    this._captureNonce(nonce)

    if (statusCode !== 200) {
      throw Object.assign(new Error('Failed to get directory'), { body, statusCode })
    }

    for (const resource in body) {
      this._knownEndpoints.set(resource, body[resource])
    }

    if (!this._knownEndpoints.has(resource)) {
      throw new Error(`Could not determine endpoint for resource ${resource}`)
    }

    return this._knownEndpoints.get(resource)
  }

  async newReg (email) {
    const [nonce, result] = await request('POST', await this._discoverEndpoint('new-reg'), {
      jws: this._account.sign({
        resource: 'new-reg',
        contact: [`mailto:${email}`]
      }, await this._getNonce())
    })
    this._captureNonce(nonce)

    if (result.statusCode === 409) {
      return this.reg(result.links.self)
    }

    return result
  }

  async reg (uri) {
    const [nonce, result] = await request('POST', uri, {
      jws: this._account.sign({
        resource: 'reg'
      }, await this._getNonce())
    })
    this._captureNonce(nonce)

    result.links.self = uri
    return result
  }

  async updateRegAgreement (regUri, agreement) {
    const [nonce, result] = await request('POST', regUri, {
      jws: this._account.sign({
        resource: 'reg',
        agreement
      }, await this._getNonce())
    })
    this._captureNonce(nonce)

    result.links.self = regUri
    return result
  }

  async newAuthz (domainName) {
    const [nonce, result] = await request('POST', await this._discoverEndpoint('new-authz'), {
      jws: this._account.sign({
        resource: 'new-authz',
        identifier: {
          type: 'dns',
          value: domainName
        }
      }, await this._getNonce())
    })
    this._captureNonce(nonce)

    return result
  }

  async challenge (uri, type, keyAuthorization) {
    const [nonce, result] = await request('POST', uri, {
      jws: this._account.sign({
        resource: 'challenge',
        type,
        keyAuthorization
      }, await this._getNonce())
    })
    this._captureNonce(nonce)

    result.links.self = uri
    return result
  }

  async pollPendingAuthz (uri, defaultRetryAfter = 5000) {
    const [, result] = await request('GET', uri)

    const { body, retryAfter, statusCode } = result
    if (statusCode === 202 && body.status === 'pending') {
      await new Promise((resolve) => {
        setTimeout(resolve, retryAfter || defaultRetryAfter)
      })
      return this.pollPendingAuthz(uri, defaultRetryAfter)
    }

    result.links.self = uri
    return result
  }

  async newCert (csr, notAfter = utc().add(90, 'days').format(), notBefore = utc().format()) {
    const [, result] = await request('POST', await this._discoverEndpoint('new-cert'), {
      accept: 'application/pkix-cert',
      jws: this._account.sign({
        resource: 'new-cert',
        csr,
        notBefore,
        notAfter
      }, await this._getNonce())
    })

    return result
  }
}

function extractLinks ({ link, location }) {
  const result = {}
  if (location) {
    result.self = location
  }

  const parsed = parseLinkHeader(link)
  if (!parsed) return result

  return Object.keys(parsed).reduce((acc, rel) => {
    acc[rel] = parsed[rel].url
    return acc
  }, result)
}

function getBody (res) {
  const { type } = parseContentType(res.headers['content-type'])
  if (type === 'application/json' || type === 'application/problem+json') {
    return getStream(res, 'utf8').then(JSON.parse)
  } else if (type === 'application/pkix-cert') {
    return getStream.buffer(res)
  } else {
    return getStream(res, 'utf8')
  }
}

async function request (method, uri, {
  jws,
  accept = 'application/json'
} = {}) {
  const res = await new Promise((resolve, reject) => {
    const { hostname, port, path } = parseUri(uri)
    const headers = { accept }
    if (jws) {
      headers['content-type'] = 'application/jose'
    }

    https.request({ method, hostname, port, path, headers })
      .on('error', reject)
      .on('response', resolve)
      .end(jws)
  })

  const {
    headers,
    headers: {
      'replay-nonce': nonce
    },
    statusCode
  } = res

  const body = await getBody(res)
  const links = extractLinks(headers)
  const retryAfter = parseInt(headers['retry-after']) || null

  return [nonce, {
    body,
    links,
    retryAfter,
    statusCode
  }]
}
