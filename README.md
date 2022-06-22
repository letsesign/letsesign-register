# letsesign-register

`letsesign-register` is an open-source command line tool for registering your root domain with the confidential eSigning service [Let's eSign](https://letsesign.org). During the registration process, it will help you set up an RSA-2048 key pair in your own [AWS KMS](https://aws.amazon.com/tw/kms/) environment so that only specified  [Let's eSign Enclave](https://github.com/letsesign/letsesign-enclave) instances can access the private key of the key pair to decrypt data encrypted using the corresponding public key. 

## How to use
```
npx letsesign-register SITE_CONFIG_JSON_FILE
```

As for how to compose the required `SITE_CONFIG_JSON_FILE`, please check [How to register your root domain with Let's eSign](https://github.com/letsesign/letsesign-docs/blob/main/HOWTO-register.md).
