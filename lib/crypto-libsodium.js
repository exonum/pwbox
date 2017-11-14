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

const sodium = require('libsodium-wrappers-sumo');

exports.scrypt = function (password, salt, options, callback) {
  setTimeout(function () {
    var dk = sodium.crypto_pwhash_scryptsalsa208sha256(
      options.dkLength,
      password,
      salt,
      options.opslimit,
      options.memlimit);

    callback(dk);
  }, 0);
};

const secretbox = exports.secretbox = function (message, nonce, key) {
  return sodium.crypto_secretbox_easy(message, nonce, key);
};

// Monkey-patches `secretbox.open` to return `false` on failure
// (as in TweetNaCl)
secretbox.open = function () {
  try {
    return sodium.crypto_secretbox_open_easy.apply(this, arguments);
  } catch (e) {
    return false;
  }
};

exports.randomBytes = sodium.randombytes_buf;
