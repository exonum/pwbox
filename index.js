'use strict';

const pwbox = require('./lib/pwbox');

/**
 * Creates a new instance of `pwbox` with the specified cryptographic module
 * injected.
 *
 * @param {String|Object} nacl
 *   module to use. Allowed string values are `'libsodium'` and `'tweetnacl'`.
 *   Alternatively, you may inject a module directly as an object.
 *
 * @api public
 */
function withCrypto (nacl) {
  if (nacl === 'libsodium') {
    nacl = require('./lib/crypto-libsodium');
  } else if (nacl === 'tweetnacl') {
    nacl = require('./lib/crypto-tweetnacl');
  }

  return pwbox(nacl);
}

module.exports = withCrypto('tweetnacl');
module.exports.withCrypto = withCrypto;
