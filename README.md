# letsesign-register

`letsesign-register` is an open-source command line tool for registering your root domain with the confidential eSigning service [Let's eSign](https://letsesign.org). During the registration process, it will help you set up an RSA key pair in your own [AWS KMS](https://aws.amazon.com/tw/kms/) environment so that only specified  [Let's eSign Enclave](https://github.com/letsesign/letsesign-enclave) instances can access the RSA private key to decrypt the data encrypted using the corresponding RSA public key. 

## How to use

Simply run the following:
```
npx letsesign-register SITE_CONFIG_JSON_FILE
```

As for how to compose the required `SITE_CONFIG_JSON_FILE`, please check [How to register your root domain with Let's eSign](https://github.com/letsesign/letsesign-register/blob/main/doc/HOWTO-register.md).


## How to build

Simply run the following:
```
git clone https://github.com/letsesign/letsesign-register.git
cd letsesign-register
npm install
npx tsc
```
Then check the `./dist` folder for the built scripts.