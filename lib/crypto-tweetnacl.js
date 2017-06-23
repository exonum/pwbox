'use strict';

const nacl = require('tweetnacl');
const scrypt = require('scrypt-async');

/**
 * Interrupt step parameter for scrypt-async.
 */
const INTERRUPT_STEP = 16384;

function shiftLeft (bits) {
  var pow2 = 1;
  for (var i = 0; i < bits; i++) {
    pow2 *= 2;
  }
  return pow2;
}

/**
 * Converts `(opslimit, memlimit)` into `(N, r, p)` triple consumable by scrypt.
 * Adapted from libsodium,
 * https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_pwhash/scryptsalsa208sha256/pwhash_scryptsalsa208sha256.c
 */
function pickParams (opslimit, memlimit) {
  var log2N, r, p, maxN, maxrp;

  // Obsolete because of the `opslimit` range checks
  // if (opslimit < 32768) {
  //   opslimit = 32768;
  // }

  r = 8;
  if (opslimit * 32 < memlimit) {
    p = 1;
    maxN = Math.floor(opslimit / (r * 4));

    for (log2N = 1; log2N < 63; log2N += 1) {
      if (shiftLeft(log2N) * 2 > maxN) break;
    }
  } else {
    maxN = Math.floor(memlimit / (r * 128));

    for (log2N = 1; log2N < 63; log2N += 1) {
      if (shiftLeft(log2N) * 2 > maxN) break;
    }

    maxrp = Math.floor(Math.floor(opslimit / 4) / shiftLeft(log2N));
    maxrp = Math.min(maxrp, 0x3fffffff);

    p = Math.floor(maxrp / r);
  }

  return { log2N: log2N, r: r, p: p };
}

/**
 * Derives a key and nonce for secret-key encryption using the scrypt hash function.
 *
 * @param {String|Uint8Array} password used in derivation
 * @param {Uint8Array} salt used in derivation
 * @param {Object} options same as in `pwbox`
 * @param {Function} callback to call when the scrypt calculation is completed
 *
 * @api private
 */
const scryptDK = exports.scrypt = function (password, salt, options, callback) {
  var params = pickParams(options.opslimit, options.memlimit);

  var scryptOptions = {
    logN: params.log2N,
    r: params.r,
    p: params.p,
    dkLen: options.dkLength,
    interruptStep: INTERRUPT_STEP,
    encoding: 'binary'
  };

  scrypt(password, salt, scryptOptions, callback);
};

// Exports for testing
scryptDK.pickParams = pickParams;

exports.randomBytes = nacl.randomBytes;
exports.secretbox = nacl.secretbox;
