import { request } from 'https'
import { parse as parseUrl } from 'url'

import getStream from 'get-stream'
import { utc } from 'moment'
import parseLinkHeader from 'parse-link-header'

function extractLinks (headers) {
  const parsed = parseLinkHeader(headers.link)
  if (!parsed) return {}

  return Object.keys(parsed).reduce((acc, rel) => {
    acc[rel] = parsed[rel].url
    return acc
  }, {})
}

export default class Server {
  constructor (root, account) {
    this._root = root
    this._account = account

    this._nonces = []
    this._directory = null
  }

  get nonce () {
    return new Promise((resolve, reject) => {
      if (this._nonces.length) {
        resolve(this._nonces.shift())
        return
      }

      const { hostname, port, path } = parseUrl(this._root)
      request({
        method: 'HEAD',
        hostname,
        port,
        path
      }).on('error', reject).on('response', (res) => {
        resolve(res.headers['replay-nonce'])
      }).end()
    })
  }

  _storeNonce (headers) {
    if (headers['replay-nonce']) {
      this._nonces.push(headers['replay-nonce'])
    }
  }

  get directory () {
    return this._directory || (this._directory = new Promise((resolve, reject) => {
      request(this._root).on('error', reject).on('response', (res) => {
        const { statusCode, headers } = res
        this._storeNonce(headers)

        if (statusCode !== 200) {
          reject(Object.assign(new Error('Failed to get directory'), { statusCode }))
        } else {
          resolve(getStream(res).then(JSON.parse))
        }
      }).end()
    }))
  }

  async register (email) {
    const { hostname, port, path } = parseUrl((await this.directory)['new-reg'])

    const nonce = await this.nonce
    return new Promise((resolve, reject) => {
      request({
        method: 'POST',
        hostname,
        port,
        path
      }).on('error', reject).on('response', (res) => {
        const { statusCode, headers } = res
        this._storeNonce(headers)
        const links = extractLinks(headers)
        links.self = headers.location

        return getStream(res).then(JSON.parse).then((payload) => {
          resolve({
            links,
            payload,
            statusCode
          })
        })
      }).end(this._account.sign({
        resource: 'new-reg',
        contact: [`mailto:${email}`]
      }, nonce))
    }).then((result) => {
      const { statusCode, links: { self } } = result

      if (statusCode === 201) {
        return result
      } else if (statusCode === 409) {
        return this.getRegistration(self)
      }
    })
  }

  async getRegistration (url) {
    const { hostname, port, path } = parseUrl(url)

    const nonce = await this.nonce
    return new Promise((resolve, reject) => {
      request({
        method: 'POST',
        hostname,
        port,
        path
      }).on('error', reject).on('response', (res) => {
        const { statusCode, headers } = res
        this._storeNonce(headers)
        const links = extractLinks(headers)
        links.self = url

        return getStream(res).then(JSON.parse).then((payload) => {
          resolve({
            links,
            payload,
            statusCode
          })
        })
      }).end(this._account.sign({ resource: 'reg' }, nonce))
    })
  }

  async acceptTermsOfService (registrationUrl, termsOfServiceUrl) {
    const { hostname, port, path } = parseUrl(registrationUrl)

    const nonce = await this.nonce
    return new Promise((resolve, reject) => {
      request({
        method: 'POST',
        hostname,
        port,
        path
      }).on('error', reject).on('response', (res) => {
        const { statusCode, headers } = res
        this._storeNonce(headers)
        const links = extractLinks(headers)
        links.self = registrationUrl

        return getStream(res).then(JSON.parse).then((payload) => {
          resolve({
            links,
            payload,
            statusCode
          })
        })
      }).end(this._account.sign({
        resource: 'reg',
        agreement: termsOfServiceUrl
      }, nonce))
    })
  }

  async authorizeIdentifier (domainName) {
    const { hostname, port, path } = parseUrl((await this.directory)['new-authz'])

    const nonce = await this.nonce
    return new Promise((resolve, reject) => {
      request({
        method: 'POST',
        hostname,
        port,
        path
      }).on('error', reject).on('response', (res) => {
        const { statusCode, headers } = res
        this._storeNonce(headers)
        const links = extractLinks(headers)
        links.self = headers.location

        return getStream(res).then(JSON.parse).then((payload) => {
          resolve({
            links,
            payload,
            statusCode
          })
        })
      }).end(this._account.sign({
        resource: 'new-authz',
        identifier: { type: 'dns', value: domainName }
      }, nonce))
    })
  }

  async meetChallenge (challengeUrl, type, keyAuthorization) {
    const { hostname, port, path } = parseUrl(challengeUrl)

    const nonce = await this.nonce
    return new Promise((resolve, reject) => {
      request({
        method: 'POST',
        hostname,
        port,
        path
      }).on('error', reject).on('response', (res) => {
        const { statusCode, headers } = res
        this._storeNonce(headers)
        const links = extractLinks(headers)
        links.self = challengeUrl

        return getStream(res).then(JSON.parse).then((payload) => {
          resolve({
            links,
            payload,
            statusCode
          })
        })
      }).end(this._account.sign({
        resource: 'challenge',
        type,
        keyAuthorization
      }, nonce))
    })
  }

  async pollPendingAuthorization (authzUrl) {
    const { hostname, port, path } = parseUrl(authzUrl)

    return new Promise((resolve, reject) => {
      request({
        method: 'GET',
        hostname,
        port,
        path
      }).on('error', reject).on('response', (res) => {
        const { statusCode } = res
        const links = { self: authzUrl }

        return getStream(res).then(JSON.parse).then((payload) => {
          resolve({
            links,
            payload,
            statusCode
          })
        })
      }).end()
    }).then((result) => {
      if (result.payload.status !== 'pending') return result

      return new Promise((resolve) => {
        setTimeout(() => resolve(), 10000)
      }).then(() => this.pollPendingAuthorization(authzUrl))
    })
  }

  async issue (csr, notAfter = utc().add(90, 'days'), notBefore = utc()) {
    const { hostname, port, path } = parseUrl((await this.directory)['new-cert'])

    const nonce = await this.nonce
    return new Promise((resolve, reject) => {
      request({
        method: 'POST',
        hostname,
        port,
        path,
        headers: { 'content-type': 'application/pkix-cert' }
      }).on('error', reject).on('response', (res) => {
        const { statusCode, headers } = res
        const links = extractLinks(headers)
        links.self = headers.location

        const encoding = headers['content-type'] === 'application/pkix-cert' ? 'base64' : 'utf8'
        return getStream(res, { encoding }).then((payload) => {
          resolve({
            links,
            payload,
            statusCode
          })
        })
      }).end(this._account.sign({
        resource: 'new-cert',
        csr,
        notBefore: utc(notBefore).format(),
        notAfter: utc(notAfter).format()
      }, nonce))
    }).then((result) => {
      const { statusCode } = result
      if (statusCode === 201) return result

      throw Object.assign(new Error('Could not issue certificate'), result)
    })
  }

  async getCert (certUrl) {
    const { hostname, port, path } = parseUrl(certUrl)
    return new Promise((resolve, reject) => {
      request({
        method: 'GET',
        hostname,
        port,
        path,
        headers: { 'content-type': 'application/pkix-cert' }
      }).on('error', reject).on('response', (res) => {
        const { statusCode, headers } = res
        const links = extractLinks(headers)
        links.self = certUrl

        const encoding = headers['content-type'] === 'application/pkix-cert' ? 'base64' : 'utf8'
        return getStream(res, { encoding }).then((payload) => {
          resolve({
            links,
            payload,
            statusCode
          })
        })
      }).end()
    }).then((result) => {
      const { statusCode } = result
      if (statusCode === 200) return result

      throw Object.assign(new Error('Could not issue certificate'), result)
    })
  }
}
