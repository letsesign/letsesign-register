#!/usr/bin/env node
const { existsSync } = require('fs');
const { resolve } = require('path');
const { register } = require('./register');
const { version } = require('../package.json');

const printUsage = () => {
  console.log(`
letsesign-register (v${version})
    
The command line tool for registering your domain with Let's eSign

Usage:

  letsesign-register SITE_CONFIG_JSON_FILE
  `);
};

const proc = async () => {
  const argv = process.argv.slice(2);

  if (argv.length !== 1) return printUsage();

  const configFullPath = resolve(process.cwd(), argv[0]);

  if (!existsSync(configFullPath)) throw new Error('ERROR: please make sure that the config file exists');

  await register(configFullPath);

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
