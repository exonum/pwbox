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
/* eslint-env node, mocha */

// It is important to verify that the constants in `crypto-constants`
// are actually correct.

const expect = require('chai').expect;
const sodium = require('libsodium-wrappers-sumo');

const constants = require('../lib/crypto-constants');

describe('crypto-constants', function () {
  it('should have valid scrypt salt length', function () {
    expect(constants.scrypt.saltLength).to.equal(sodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
  });

  it('should have valid secretbox key length', function () {
    expect(constants.secretbox.keyLength).to.equal(sodium.crypto_secretbox_KEYBYTES);
  });

  it('should have valid secretbox nonce length', function () {
    expect(constants.secretbox.nonceLength).to.equal(sodium.crypto_secretbox_NONCEBYTES);
  });

  it('should have reasonable default opslimit', function () {
    expect(constants.scrypt.defaultOpslimit).to.equal(sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE);
  });

  it('should have reasonable default memlimit', function () {
    expect(constants.scrypt.defaultMemlimit).to.equal(sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);
  });

  it('should have correct minimum opslimit', function () {
    expect(constants.scrypt.minOpslimit).to.equal(sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN);
  });

  it('should have correct minimum memlimit', function () {
    expect(constants.scrypt.minMemlimit).to.equal(sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN);
  });

  it('should have reasonable maximum opslimit', function () {
    expect(constants.scrypt.maxOpslimit).to.equal(sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE);
  });

  it('should have reasonable maximum memlimit', function () {
    expect(constants.scrypt.maxMemlimit).to.equal(sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE);
  });
});
