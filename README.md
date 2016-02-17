# wilee (Wile E.)

Command line tool for interacting with
[ACME](https://ietf-wg-acme.github.io/acme/) servers. Provides a partial ACME
implementation, supports account registration, DNS identifier authorization, DNS
challenges, and certificate issuance.

## Installation

```shell
npm install -g wilee
```

Requires [Node.js 5.6.0 or above](https://nodejs.org/en/). Depends on
[`ursa`](https://www.npmjs.com/package/ursa) for computing public keys. `ursa`
requires OpenSSL bindings to be available.

## Usage

Run the following to see the commands available to you:

```shell
wilee --help
```

```
Usage: wilee [global options] <command> [options]

Commands:
  new-reg <email>     Create a new registration for the account key
  new-authz <domain>  Authorize a domain name identifier
  new-cert <csr>      Submit a certificate signing request

Global options:
  --account, -a    File location of the RSA private key which should be used as
                   the Account Key (in PEM format)           [string] [required]
  --directory, -d  URI of the directory resource on the ACME server
        [string] [default: "https://acme-staging.api.letsencrypt.org/directory"]

Options:
  --help  Show help                                                    [boolean]

Find more usage information at https://github.com/novemberborn/wilee
```

Each command requires you to specify your private account key. This is how you
identify yourself to the ACME server. Use the `--account` option with the path
of the private key file.

You'll need to specify which ACME server you wish to use. By default this is
[Let's Encrypt's staging
server](https://community.letsencrypt.org/t/testing-against-the-lets-encrypt-staging-environment/6763)
which does not issue valid certificates.

Specify `--directory https://acme-v01.api.letsencrypt.org/directory` to use
[Let's Encrypt's](https://letsencrypt.org/) production server. Note that [rate
limits](https://community.letsencrypt.org/t/rate-limits-for-lets-encrypt/6769)
apply, so it's recommended you try with the staging server first.

Before we look at the individual commands you'll have to generate some private
keys and a certificate signing request.

### Prerequisites

`wilee` does not generate private keys or certificate signing requests. You'll
need to generate those first. This assumes you want to use OpenSSL.

Generate your private account key:

```shell
openssl genrsa -out account.pem 4096
```

Generate the private key for the certificate you want issued:

```shell
openssl genrsa -out key.pem 2048
```

Generate the certificate signing request in DER form:

```shell
openssl req -new -sha256 -key key.pem -outform der -out csr.der
```

Please see this [Google Developers
tutorial](https://developers.google.com/web/fundamentals/security/encrypt-in-transit/generating-keys-and-csr?hl=en#generate-a-csr)
on how to answer the CSR questions.

### Register with the ACME server

Use the `new-reg` command to register with the ACME server:

```shell
wilee new-reg --help
```

```
Usage: wilee [global options] new-reg <email> [options]

Provide the email address you wish the ACME server to contact you on if
necessary.

Global options:
  --account, -a    File location of the RSA private key which should be used as
                   the Account Key (in PEM format)           [string] [required]
  --directory, -d  URI of the directory resource on the ACME server
        [string] [default: "https://acme-staging.api.letsencrypt.org/directory"]

Options:
  --help  Show help                                                    [boolean]

Examples:
  wilee --account account.pem new-reg       Register your account with
  example@example.com                       example@example.com as the contact
                                            address
```

Note that `MX` records must exist for the email address. You'll likely be asked
to agree to the terms of service of the ACME server.

### Authorize your account for a domain

Use the `new-authz` command to authorize your account for a domain. The ACME
server will issue challenges to prove you control the domain in question.

```shell
wilee new-authz --help
```

```
Usage: wilee [global options] new-authz <domain> [options]

Pass the domain name you wish to authorize your account for.

Global options:
  --account, -a    File location of the RSA private key which should be used as
                   the Account Key (in PEM format)           [string] [required]
  --directory, -d  URI of the directory resource on the ACME server
        [string] [default: "https://acme-staging.api.letsencrypt.org/directory"]

Options:
  --help  Show help                                                    [boolean]

Examples:
  wilee --account account.pem new-authz     Authorize your account for
  example.com                               example.com
```

`wilee` only supports the DNS challenge. It'll prompt you to create a `TXT`
record at the `_acme-challenge` subdomain with a specific value. It'll poll DNS
until the record exists, then it'll ask the ACME server to verify. Once
successful you'll be able to submit certificate signing requests.

### Creating certificates

Once you've authorized your account for a domain you can create a certificate.
Use the `new-cert` command.

```shell
wilee new-cert --help
```

```
Usage: wilee [global options] new-cert <csr> [options]

Submit a certificate signing request. The CSR file must be in DER format.

Your account must have previously been authorized for the domains included in
the certificate. Other restrictions may apply, depending on the ACME server.

--not-before and --not-after may be ignored by ACME servers.

Global options:
  --account, -a    File location of the RSA private key which should be used as
                   the Account Key (in PEM format)           [string] [required]
  --directory, -d  URI of the directory resource on the ACME server
        [string] [default: "https://acme-staging.api.letsencrypt.org/directory"]

Options:
  --help        Show help                                              [boolean]
  --not-before  ISO8601-formatted timestamp to restrict when the certificate
                becomes valid
                      [string] [default: Time when the certificate is requested]
  --not-after   ISO8601-formatted timestamp to restrict when the certificate
                ceases to be valid
                  [string] [default: 90 days after the certificate is requested]
  --out, -o     If provided, the path the certificate should be written to
                                                                        [string]

Examples:
  wilee --account account.pem new-cert
  csr.der -o cert.der
```

Make sure to use a certificate signing request for authorized domains. Different
ACME servers may have different requirements. You could use the `--not-before`
and `--not-after` options to change when the certificate is valid. Let's Encrypt
ignores these though.

Specify `--out` to write the certificate to a file on your computer. Else the
certificate's URL is printed. You'll be able to download the certificate from
there.

The certificate will be in `DER` format. It can be used with the private key
`key.pem` you generated earlier. You may need to convert these files for use
with your web server.

Don't forget that the certificate will expire!

## Background

`wilee` was created to learn the ACME protocol. You'll probably want to use
better developed tools like the [official
client](https://letsencrypt.org/howitworks/) or
[`letsencrypt`](https://letsencrypt.org/howitworks/) for Node.js.

Those tools don't support the DNS challenge though, so `wilee` could come in
handy if you can't meet any of the other challenge types.
