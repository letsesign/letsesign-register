#!/usr/bin/env node
const { existsSync } = require('fs');
const { resolve } = require('path');
const { version } = require('../package.json');
const register = require('../lib/register');

const printUsage = () => {
  console.log(`
Let's eSign Register (v${version})
    
The tool for Let's eSign users to obtain the
registration token and update the registration information.

Usage:
    letsesign-register CONFIG_FILE
  `);
};

const proc = async () => {
  const argv = process.argv.slice(2);

  if (argv.length !== 1) return printUsage();

  const configFullPath = resolve(process.cwd(), argv[0]);

  if (!existsSync(configFullPath)) throw new Error('ERROR: please make sure that the config file exists');

  await register.run(configFullPath);

  return '';
};

proc()
  .then((result) => {
    if (result !== undefined) {
      console.log(result);
    }
  })
  .catch((error) => {
    console.error(error);
  });
