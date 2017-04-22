'use strict';

const pwbox = require('./lib/pwbox');

module.exports = pwbox('tweetnacl');
module.exports.withCrypto = pwbox;
