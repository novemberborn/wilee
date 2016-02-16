import https from 'https'
import { parse as parseUri } from 'url'

import getStream from 'get-stream'
import { utc } from 'moment'
import parseLinkHeader from 'parse-link-header'

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

    const { hostname, port, path } = parseUri(this._directoryUri)
    const { nonce } = await request({
      method: 'HEAD',
      hostname,
      port,
      path,
      as: null
    }).end()
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

    const { hostname, port, path } = parseUri(this._directoryUri)
    const { body, nonce, statusCode } = await request({
      method: 'GET',
      hostname,
      port,
      path
    }).end()

    this._captureNonce(nonce)

    if (statusCode !== 200) {
      throw Object.assign(new Error('Failed to get directory'), { body, statusCode })
    }

    for (const resource in body) {
      const uri = body[resource]
      const { hostname, port, path } = parseUri(uri)
      this._knownEndpoints.set(resource, Object.freeze({ hostname, port, path, uri }))
    }

    if (!this._knownEndpoints.has(resource)) {
      throw new Error(`Could not determine endpoint for resource ${resource}`)
    }

    return this._knownEndpoints.get(resource)
  }

  async newReg (email) {
    const { hostname, port, path } = await this._discoverEndpoint('new-reg')

    const { body, links, nonce, statusCode } = await request({
      method: 'POST',
      hostname,
      port,
      path
    }).end(this._account.sign({
      resource: 'new-reg',
      contact: [`mailto:${email}`]
    }, await this._getNonce()))

    this._captureNonce(nonce)

    if (statusCode === 409) {
      return this.reg(links.self)
    }

    return {
      body,
      links,
      statusCode
    }
  }

  async reg (uri) {
    const { hostname, port, path } = parseUri(uri)

    const { body, links, nonce, statusCode } = await request({
      method: 'POST',
      hostname,
      port,
      path
    }).end(this._account.sign({
      resource: 'reg'
    }, await this._getNonce()))

    this._captureNonce(nonce)

    links.self = uri
    return {
      body,
      links,
      statusCode
    }
  }

  async updateRegAgreement (regUri, agreement) {
    const { hostname, port, path } = parseUri(regUri)

    const { body, links, nonce, statusCode } = await request({
      method: 'POST',
      hostname,
      port,
      path
    }).end(this._account.sign({
      resource: 'reg',
      agreement
    }, await this._getNonce()))

    this._captureNonce(nonce)

    links.self = regUri
    return {
      body,
      links,
      statusCode
    }
  }

  async newAuthz (domainName) {
    const { hostname, port, path } = await this._discoverEndpoint('new-authz')

    const { body, links, nonce, statusCode } = await request({
      method: 'POST',
      hostname,
      port,
      path
    }).end(this._account.sign({
      resource: 'new-authz',
      identifier: {
        type: 'dns',
        value: domainName
      }
    }, await this._getNonce()))

    this._captureNonce(nonce)

    return {
      links,
      body,
      statusCode
    }
  }

  async challenge (uri, type, keyAuthorization) {
    const { hostname, port, path } = parseUri(uri)

    const { body, links, nonce, statusCode } = await request({
      method: 'POST',
      hostname,
      port,
      path
    }).end(this._account.sign({
      resource: 'challenge',
      type,
      keyAuthorization
    }, await this._getNonce()))

    this._captureNonce(nonce)

    links.self = uri
    return {
      links,
      body,
      statusCode
    }
  }

  async pollPendingAuthz (uri, defaultRetryAfter = 5000) {
    const { hostname, port, path } = parseUri(uri)

    const { body, headers, links, statusCode } = await request({
      method: 'GET',
      hostname,
      port,
      path
    }).end()

    links.self = uri

    if (statusCode === 202 && body.status === 'pending') {
      const retryAfter = parseInt(headers['retry-after']) || defaultRetryAfter
      await new Promise((resolve) => {
        setTimeout(resolve, retryAfter)
      })
      return this.pollPendingAuthz(uri, defaultRetryAfter)
    }

    return {
      body,
      links,
      statusCode
    }
  }

  async newCert (csr, notAfter = utc().add(90, 'days').format(), notBefore = utc().format()) {
    const { hostname, port, path } = await this._discoverEndpoint('new-cert')

    const { body, links, statusCode } = await request({
      method: 'POST',
      hostname,
      port,
      path,
      headers: { 'content-type': 'application/pkix-cert' },
      as (res) {
        return res.headers['content-type'] === 'application/pkix-cert' ? 'buffer' : 'json'
      }
    }).end(this._account.sign({
      resource: 'new-cert',
      csr,
      notBefore,
      notAfter
    }, await this._getNonce()))

    return {
      body,
      links,
      statusCode
    }
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

function request ({
  method,
  hostname,
  port,
  path,
  headers,
  as = 'json'
}) {
  let req = null
  const promise = new Promise((resolve, reject) => {
    req = https.request({ method, hostname, port, path, headers })
      .on('error', reject)
      .on('response', (res) => {
        const {
          headers,
          headers: {
            'replay-nonce': nonce
          },
          statusCode
        } = res
        const links = extractLinks(headers)

        let fetchingBody = null
        switch (typeof as === 'function' ? as(res) : as) {
          case 'json':
            fetchingBody = getStream(res, 'utf8').then(JSON.parse)
            break
          case 'buffer':
            fetchingBody = getStream.buffer(res)
            break
          default:
            fetchingBody = Promise.resolve(null)
        }

        resolve(fetchingBody.then((body) => {
          return {
            body,
            headers,
            links,
            nonce,
            raw: res,
            statusCode
          }
        }))
      })
  })

  return {
    end (requestBody) {
      req.end(requestBody)
      return promise
    }
  }
}
