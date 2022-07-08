const { Validator } = require('jsonschema');
const fs = require('fs');
const readline = require('readline');
const axios = require('axios');
const tldjs = require('tldjs');
const crypto = require('crypto');

const kmsUtil = require('./kms-util');

const requestEnterInput = (message: string) => {
  return new Promise<void>((resolve) => {
    const readLineInterface = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });

    readLineInterface.question(message, async () => {
      resolve();
      readLineInterface.close();
    });
  });
};

const checkConfig = (param: any) => {
  const schema = {
    type: 'object',
    properties: {
      config: {
        type: 'object',
        properties: {
          rootDomain: {
            type: 'string',
            minLength: 1
          },
          bearerSecret: {
            type: 'string',
            minLength: 16,
            maxLength: 64
          },
          awsAccessKeyID: {
            type: 'string',
            minLength: 1
          },
          awsSecretAccessKey: {
            type: 'string',
            minLength: 1
          },
          signerAppURL: { type: 'string' },
          enhancedPrivacy: { type: 'boolean' }
        },
        required: [
          'rootDomain',
          'bearerSecret',
          'awsAccessKeyID',
          'awsSecretAccessKey',
          'signerAppURL',
          'enhancedPrivacy'
        ]
      },
      sesConfig: {
        type: 'object',
        properties: {
          sesSMTPUsername: {
            type: 'string',
            minLength: 1
          },
          sesSMTPPassword: {
            type: 'string',
            minLength: 1
          }
        },
        required: ['sesSMTPUsername', 'sesSMTPPassword']
      },
      twilioConfig: {
        type: 'object',
        properties: {
          apiSID: {
            type: 'string',
            minLength: 1
          },
          apiSecret: {
            type: 'string',
            minLength: 1
          },
          serviceSID: {
            type: 'string',
            minLength: 1
          }
        },
        required: ['apiSID', 'apiSecret', 'serviceSID']
      }
    },
    required: ['config', 'sesConfig', 'twilioConfig']
  };

  return new Validator().validate(param, schema);
};

const startRegisteration = async (payload: any) => {
  const postResult = await axios.post(
    'https://register.letsesign.net/v1_1/start-registration',
    JSON.stringify(payload),
    {
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json'
      }
    }
  );
  if (postResult.status !== 200) {
    throw new Error(`start registration API with error: ${postResult.statusText}`);
  }
  const apiResp = postResult.data;
  return apiResp;
};

const completeRegisteration = async (payload: any) => {
  const postResult = await axios.post(
    'https://register.letsesign.net/v1_1/complete-registration',
    JSON.stringify(payload),
    {
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json'
      }
    }
  );

  const apiResp = postResult.data;
  if (postResult.status === 200) {
    apiResp.code = 0;
  }
  return apiResp;
};

const encryptData = (dataBuffer: string, kmsPubKey: string) => {
  const dataKey = crypto.randomBytes(32);
  const IV = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', dataKey, IV);

  let encryptedData = cipher.update(dataBuffer, 'utf8', 'base64');
  encryptedData += cipher.final('base64');

  const encryptedDataKey = crypto
    .publicEncrypt(
      {
        key: kmsPubKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      dataKey
    )
    .toString('base64');

  const dataIV = IV.toString('base64');

  return {
    encryptedData,
    encryptedDataKey,
    dataIV
  };
};

export const register = async (configPath: string) => {
  // 1. show terms notice
  await requestEnterInput(
    "\nPress Enter if you have read and agreed to the Let's eSign API Terms of Service\n(https://github.com/letsesign/letsesign-register/blob/main/doc/TermsOfService.md)\n..."
  );

  // 2. check if config is correct
  let siteSetting = null;
  let emailConfig = null;
  let twilioConfig = null;
  const configData = JSON.parse(fs.readFileSync(configPath).toString('utf-8'));

  const checkResult = checkConfig(configData);
  if (!checkResult.valid) {
    throw checkResult.errors;
  } else if (configData.config.rootDomain !== tldjs.getDomain(configData.config.rootDomain)) {
    throw new Error('ERROR: please fill a valid root domain');
  } else {
    siteSetting = configData.config;
    emailConfig = configData.sesConfig;
    emailConfig.serviceProvider = 'ses';
    emailConfig.sesDomain = siteSetting.rootDomain.startsWith('letsesign.')
      ? siteSetting.rootDomain
      : `letsesign.${siteSetting.rootDomain}`;
    twilioConfig = configData.twilioConfig;
  }

  // 3. setup KMS key
  const kmsKeySetting = await kmsUtil.setupKey(siteSetting.awsAccessKeyID, siteSetting.awsSecretAccessKey);

  // 4. call registration API
  const startRegResult = await startRegisteration({
    siteSetting: {
      rootDomain: siteSetting.rootDomain,
      signerAppURL: siteSetting.signerAppURL,
      enhancedPrivacy: siteSetting.enhancedPrivacy
    },
    kmsConfig: {
      kmsKeyARN: kmsKeySetting.kmsKeyArn
    },
    emailConfigCipher: {
      encData: encryptData(
        JSON.stringify({ emailConfig, bearerSecret: siteSetting.bearerSecret }),
        kmsKeySetting.kmsPubKey
      ),
      hash: crypto.createHash('sha256').update(JSON.stringify(emailConfig)).digest('hex')
    },
    twilioConfigCipher: {
      encData: encryptData(
        JSON.stringify({ twilioConfig, bearerSecret: siteSetting.bearerSecret }),
        kmsKeySetting.kmsPubKey
      ),
      hash: crypto.createHash('sha256').update(JSON.stringify(twilioConfig)).digest('hex')
    }
  });
  console.log('\n');
  console.log('---------------------------------------------------------------------------------------------------\n');
  console.log(`TXT   ${startRegResult.txtRecordName}   ${startRegResult.txtRecordValue}\n`);
  console.log('---------------------------------------------------------------------------------------------------\n');
  await requestEnterInput('Press Enter after adding the above entry in your DNS records for domain verification\n...');

  let isRegistrationDone = false;
  while (!isRegistrationDone) {
    const verifyResult = await completeRegisteration({
      session: startRegResult.session
    });

    if (verifyResult.code === 0) {
      const envListContent = [
        `apiKey=${verifyResult.apiToken}`,
        `bearerSecret=${siteSetting.bearerSecret}`,
        `awsAccessKeyID=${siteSetting.awsAccessKeyID}`,
        `awsSecretAccessKey=${siteSetting.awsSecretAccessKey}`,
        ''
      ].join('\n');

      fs.writeFileSync('env.list', envListContent);
      console.log(`\nSuccessfully verified. Please check the env.list file in the current directory.\n`);
      isRegistrationDone = true;
    } else if (verifyResult.code === 3) {
      await requestEnterInput(
        'Cannot verify the specified DNS entry. Please wait for a bit till DNS propagates and then press Enter again\n...'
      );
    } else {
      throw verifyResult;
    }
  }
};
