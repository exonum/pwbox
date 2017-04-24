'use strict';

const serializer = require('./serializer');
const constants = require('./crypto-constants');
const objectAssign = Object.assign || require('object-assign');
const uint8ArrayFill = Uint8Array.prototype.fill ||
  function (value) {
    for (var i = 0; i < this.length; i++) {
      this[i] = value;
    }
  };

// TODO: move to utils?

function promisify (f) {
  return function () {
    var args = Array.prototype.slice.call(arguments);
    // This assumes that the last argument of the function before the callback
    // is not a function
    if (typeof args[args.length - 1] !== 'function') {
       // Attempt to use promises
      if (typeof Promise !== 'function') {
        throw new Error('No Promise function detected, use callbacks');
      }

      var self = this;
      return new Promise(function (resolve, reject) {
        f.apply(self, args.concat(function (err, result) {
          if (err) {
            reject(err);
          } else {
            resolve(result);
          }
        }));
      });
    } else {
      return f.apply(this, args);
    }
  };
}

/**
 * Creates a new instance of `pwbox` with the specified cryptographic module
 * injected.
 *
 * @api private
 */
function createPwbox (nacl) {
  // Copy constants to the module to avoid specifying them explicitly within each
  // module.
  for (var algo in constants) {
    for (var name in constants[algo]) {
      nacl[algo][name] = constants[algo][name];
    }
  }

  const _defaultOptions = {
    salt: null,
    opslimit: nacl.scrypt.defaultOpslimit,
    memlimit: nacl.scrypt.defaultMemlimit,
    encoding: 'binary'
  };

  /**
   * @api private
   */
  function _pwbox (message, password, options, callback) {
    if (typeof options === 'function') {
      callback = options;
      options = {};
    }
    options = objectAssign({}, _defaultOptions, options);

    var encoding = options.encoding;
    delete options.encoding;

    options.dkLength = nacl.secretbox.keyLength + nacl.secretbox.nonceLength;
    var salt = options.salt || nacl.randomBytes(nacl.scrypt.saltLength);

    nacl.scrypt(password, salt, options, function (dk) {
      var key = dk.subarray(0, nacl.secretbox.keyLength);
      var nonce = dk.subarray(nacl.secretbox.keyLength);

      var ciphertext = nacl.secretbox(message, nonce, key);
      var result = {
        algorithm: {
          id: 'scrypt',
          memlimit: options.memlimit,
          opslimit: options.opslimit
        },
        salt: salt,
        ciphertext: ciphertext
      };
      if (encoding === 'binary') {
        result = serializer.serialize(result);
      }

      uint8ArrayFill.call(dk, 0);
      uint8ArrayFill.call(key, 0);
      uint8ArrayFill.call(nonce, 0);

      callback(null, result);
    });
  }

  /**
   * @api private
   */
  function _pwboxOpen (box, password, callback) {
    if (box instanceof Uint8Array) {
      // Deserialize the box first
      box = serializer.deserialize(box);
    }

    var algoId = box.algorithm.id;
    if (algoId !== 'scrypt') {
      callback(new Error('Unknown pwhash algorithm id: ' + algoId));
      return;
    }

    var options = {
      memlimit: box.algorithm.memlimit,
      opslimit: box.algorithm.opslimit,
      dkLength: nacl.secretbox.keyLength + nacl.secretbox.nonceLength
    };

    nacl.scrypt(password, box.salt, options, function (dk) {
      var key = dk.subarray(0, nacl.secretbox.keyLength);
      var nonce = dk.subarray(nacl.secretbox.keyLength);
      var message = nacl.secretbox.open(box.ciphertext, nonce, key);

      uint8ArrayFill.call(dk, 0);
      uint8ArrayFill.call(key, 0);
      uint8ArrayFill.call(nonce, 0);

      if (!message) {
        callback(new Error('Box corrupted'));
      } else {
        callback(null, message);
      }
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
  pwbox.saltLength = nacl.scrypt.saltLength;
  pwbox.defaultOpslimit = nacl.scrypt.defaultOpslimit;
  pwbox.defaultMemlimit = nacl.scrypt.defaultMemlimit;

  return pwbox;
}

module.exports = createPwbox;
