'use strict';

const serializer = require('./serializer');
const constants = require('./crypto-constants');

/**
 * Creates a new instance of `pwbox` with the specified cryptographic module
 * injected.
 *
 * @param {String|Object} crypto
 *   module to use. Allowed string values are `'libsodium'` and `'tweetnacl'`.
 *   Alternatively, you may inject a module directly as an object.
 *
 * @api public
 */
function createPwbox(crypto) {

if (crypto === 'libsodium') {
  crypto = require('./crypto-libsodium');
} else if (crypto === 'tweetnacl') {
  crypto = require('./crypto-tweetnacl');
}

// Copy constants to the module to avoid specifying them explicitly within each
// module.
for (var algo in constants) {
  for (var name in constants[algo]) {
    crypto[algo][name] = constants[algo][name];
  }
}

// TODO: move to utils?

function promisify(f) {
  return function() {
    var args = Array.prototype.slice.call(arguments);
    // This assumes that the last argument of the function before the callback
    // is not a function
    if (typeof(args[args.length - 1]) !== 'function') {
      // Attempt to use promises
      if (typeof(Promise) !== 'function') {
        throw new Error('No Promise function detected, use callbacks');
      }
      return new Promise(function(resolve, cancel) {
        f.apply(this, args.concat(resolve));
      });
    } else {
      return f.apply(this, args);
    }
  }
}

const _defaultOptions = {
  salt: null,
  opslimit: crypto.scrypt.defaultOpslimit,
  memlimit: crypto.scrypt.defaultMemlimit,
  encoding: 'binary'
};

/**
 * @api private
 */
function _pwbox(message, password, options, callback) {
  if (typeof(options) === 'function') {
    callback = options;
    options = {};
  }
  options = Object.assign({}, _defaultOptions, options);

  var encoding = options.encoding;
  delete options.encoding;

  options.dkLength = crypto.secretbox.keyLength + crypto.secretbox.nonceLength;
  var salt = options.salt || crypto.randomBytes(crypto.scrypt.saltLength);

  crypto.scrypt(password, salt, options, function(dk) {
    var key = dk.subarray(0, crypto.secretbox.keyLength);
    var nonce = dk.subarray(crypto.secretbox.keyLength);

    var ciphertext = crypto.secretbox(message, nonce, key);
    var result = {
      algorithm: {
        id: 'scrypt',
        memlimit: options.memlimit,
        opslimit: options.opslimit
      },
      salt: salt,
      ciphertext: ciphertext
    }
    if (encoding === 'binary') {
      result = serializer.serialize(result);
    }

    dk.fill(0);
    key.fill(0);
    nonce.fill(0);

    callback(result);
  })
}

/**
 * @api private
 */
function _pwboxOpen(box, password, callback) {
  if (box instanceof Uint8Array) {
    // Deserialize the box first
    box = serializer.deserialize(box);
  }

  var algoId = box.algorithm.id;
  if (algoId !== 'scrypt') {
    callback(false); // Unknown pwhash algorithm id
  }

  var options = {
    memlimit: box.algorithm.memlimit,
    opslimit: box.algorithm.opslimit,
    dkLength: crypto.secretbox.keyLength + crypto.secretbox.nonceLength
  };

  crypto.scrypt(password, box.salt, options, function(dk) {
    var key = dk.subarray(0, crypto.secretbox.keyLength);
    var nonce = dk.subarray(crypto.secretbox.keyLength);
    var message = crypto.secretbox.open(box.ciphertext, nonce, key);

    dk.fill(0);
    key.fill(0);
    nonce.fill(0);

    callback(message); // Handles the case with box corruption
  });
}

/**
 * @function pwbox
 * Performs password-based encryption using scrypt for key derivation and
 * NaCl's secretbox for symmetric encryption.
 *
 * @param {Uint8Array} message message to encrypt
 * @param {Uint8Array|string} password
 * @param {?Object} options encryption options
 * @param {?Uint8Array} options.salt
 *   salt to use in derivation. You should *never* specify the salt manually,
 *   except for testing purposes
 * @param {?Number} options.opslimit
 *   `opslimit` for scrypt (same meaning as in NaCl/libsodium). Default is
 *   FIXME
 * @param {?Number} options.memlimit
 *   `memlimit` for scrypt (same meaning as in NaCl/libsodium). Default is
 *   FIXME
 * @param {pwboxCallback} callback
 *
 * @returns {?Promise} if the function is called without the callback
 */
const pwbox = promisify(_pwbox);

/**
 * @callback pwboxCallback
 * Callback for the `pwbox` function.
 *
 * @param {Uint8Array|Object} result
 *   byte array or raw object containing encrypted message and encryption parameters
 *   (such as the algorithm used and the salt)
 * @param {String} result.algorithm.id
 *   algorithm identifier, always `'scrypt'`
 * @param {Number} result.algorithm.memlimit
 * @param {Number} result.algorithm.opslimit
 * @param {Uint8Array} result.salt
 * @param {Uint8Array} result.ciphertext
 */

/**
 * @function
 * @name pwbox.open
 * Decrypts a previously encrypted message.
 */
pwbox.open = promisify(_pwboxOpen);
pwbox.overheadLength = serializer.overheadLength;
pwbox.saltLength = crypto.scrypt.saltLength;
pwbox.defaultOpslimit = crypto.scrypt.defaultOpslimit;
pwbox.defaultMemlimit = crypto.scrypt.defaultMemlimit;

return pwbox;

}

module.exports = createPwbox;
