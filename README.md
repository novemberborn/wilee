Generating the account keys:

```shell
openssl genrsa -out account 4096
openssl rsa -in account -pubout -out account.pub
```

Generating the certificate private key:

```shell
openssl genrsa -out key.pem 2048
```

Generate the certificate signing request in DER form:

```shell
openssl req -new -sha256 -key key.pem -outform der -out csr.der
```
