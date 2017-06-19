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
});
