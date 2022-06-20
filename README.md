# Let's eSign Register

Let's eSign Register is an open source tool for registering your root domain with the confidential eSigning service [Let's eSign](https://letsesign.org). During the registration process, it will help you set up an RSA-2048 key pair in your own [AWS KMS](https://aws.amazon.com/tw/kms/) environment so that only [Let's eSign Enclave](https://github.com/letsesign/letsesign-enclave) can access the RSA-2048 private key to decrypt data encrypted using the corresponding RSA-2048 public key. 

## How to use
```
npx letsesign-register CONFIG_FILE
```

As for how to compose the required `CONFIG_FILE`, check [How to register your root domain with Let's eSign](https://github.com/letsesign/letsesign-docs/blob/main/HOWTO-register.md).
