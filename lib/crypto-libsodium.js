'use strict';

const sodium = require('libsodium-wrappers-sumo');

function scryptDeriveKey(password, salt, options, callback) {
  setTimeout(function() {
    var dk = sodium.crypto_pwhash_scryptsalsa208sha256(
      options.dkLength,
      password,
      salt,
      options.opslimit,
      options.memlimit);
    callback(dk);
  }, 0);
}

function secretbox(message, nonce, key) {
  return sodium.crypto_secretbox_easy(message, nonce, key);
}
secretbox.open = sodium.crypto_secretbox_open_easy;

module.exports = {
  randomBytes: sodium.randombytes_buf,
  secretbox: secretbox,
  scrypt: scryptDeriveKey
};
