/**
 * @license
 * Copyright 2017 The Exonum Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
  switch (nacl) {
    case 'libsodium':
      nacl = require('./lib/crypto-libsodium');
      break;
    case 'tweetnacl':
      nacl = require('./lib/crypto-tweetnacl');
      break;
    default:
      // Do nothing
  }

  return pwbox(nacl);
}

module.exports = withCrypto('tweetnacl');
module.exports.withCrypto = withCrypto;
