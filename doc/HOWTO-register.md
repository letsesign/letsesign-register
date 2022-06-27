# How to register your root domain with Let's eSign

To register your root domain with Let's eSign, you need to have the privilege to manage the DNS records of your root domain. You also need to be an administrator of an AWS account. To start the registration process, run the following:

   ```
   npx letsesign-register SITE_CONFIG_JSON_FILE
   ```

Here `letsesign-register` is an open-source command line tool, while `SITE_CONFIG_JSON_FILE`, which has 3 sections, has the following format:

   ```
   {
       "config": {
           "rootDomain": "",
           "bearerSecret": "",
           "awsAccessKeyID": "",
           "awsSecretAccessKey": "",
           "signerAppURL": "https://signer.letsesign.org/#/esign",
           "enhancedPrivacy": false
       },
       "sesConfig": {
           "sesSMTPUsername": "",
           "sesSMTPPassword": ""
       },
       "twilioConfig": {
           "apiSID": "",
           "apiSecret": "",
           "serviceSID": ""
       }
  }
  ```
  
- In the `config` section, you need to set a secret string named `bearerSecret`, in addition to your `awsAccessKeyID` and `awsSecretAccessKey`, which can be obtained by the steps described in [Getting Your AWS Credentials](https://docs.aws.amazon.com/sdk-for-javascript/v2/developer-guide/getting-your-credentials.html). If you are an advanced user and want to minimize the privilege of the credentials used here, it suffices to grant the corresponding IAM user the right to perform `kms:*` actions only. Note `letsesign-register` will not let `bearerSecret`, `awsAccessKeyID` and `awsSecretAccessKey` leave your machine.

   Leave `signerAppURL` and `enhancedPrivacy` unchanged for now, and don't forget to set your `rootDomain`.
  
- To fill up the `sesConfig` section, follow the instructions in [How to bring your own AWS SES credential](https://github.com/letsesign/letsesign-register/blob/main/doc/HOWTO-ses.md). This is for sending the request and notification emails.
  
- To fill up the `twilioConfig` section, follow the instructions in [How to bring your own Twilio Verify API Key](https://github.com/letsesign/letsesign-register/blob/main/doc/HOWTO-twilio.md). This is for sending the SMS verification messages.
 
`letsesign-register` will create an [AWS KMS](https://aws.amazon.com/kms/) key pair and set the corresponding key policy for you. The key pair and the key policy jointly can guarantee that only the isolated [Let's eSign Enclave](https://github.com/letsesign/letsesign-enclave) can decrypt and process the encrypted data. In the context of the current Let's eSign line of products, the data to be encrypted include:

- All the documents to be signed
- The credentials in the `sesConfig` section
- The credentials in the `twilioConfig` section

Check [here](https://aws.amazon.com/kms/pricing/) for the pricing of AWS KMS.
 
## The registration process 

After running `npx letsesign-register SITE_CONFIG_JSON_FILE`, you will be asked to agree to the terms of service and to complete the DNS validation. Once completed, you will get an `env.lst` file which is essential to deploying [Let's eSign API Server](https://github.com/letsesign/letsesign-api-server). The `env.list` file encapsulates the required API key for accessing the confidential eSigning service provided by Let's eSign.

Note you can re-run `letsesign-register` to update your registration info and to obtain a new `env.list` file to replace the old one.

## On the `bearerSecret`

The presence of `bearerSecret` is to make it impossible for Let's eSign to use your encrypted credentials to serve other customers. Please check Let's eSign API Server and Let's eSign Enclave for the details of the mechanism. You should populate the field with a long random string and keep it secret.
