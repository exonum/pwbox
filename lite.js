'use strict';

const nacl = require('./lib/crypto-tweetnacl');
module.exports = require('./lib/pwbox')(nacl);
