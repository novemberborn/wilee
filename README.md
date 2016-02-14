Generating the account keys:

```shell
openssl genrsa -out account 4096
openssl rsa -in account -pubout -out account.pub
```

Generating the certificate private key:

```shell
openssl genrsa -out cert.key 2048
```
