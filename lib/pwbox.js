'use strict';

const objectAssign = Object.assign || require('object-assign');

// Uint8Array.prototype.fill simplified ponyfill (for PhantomJS, mostly)
const uint8ArrayFill = Uint8Array.prototype.fill ||
  function (value) {
    for (var i = 0; i < this.length; i++) {
      this[i] = value;
    }
  };

const serializer = require('./serializer');
const constants = require('./crypto-constants');
const utils = require('./utils');

/**
 * Creates a new instance of `pwbox` with the specified cryptographic module
 * injected.
 *
 * @api private
 */
module.exports = function createPwbox (nacl) {
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

  function _pwboxOpen (box, password, callback) {
    if (box instanceof Uint8Array) {
      // Deserialize the box first
      box = serializer.deserialize(box);
    }

    var algoId = box.algorithm.id;
    if (algoId !== 'scrypt') {
      // Needs an async call to conform to the general behavior:
      // `pwbox.open` should *always* return before the callback is called
      setTimeout(function () {
        callback(new Error('Unknown pwhash algorithm id: ' + algoId));
      });
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
   * Performs password-based encryption using scrypt for key derivation and
   * NaCl's secretbox for symmetric encryption.
   *
   * @param {Uint8Array} message
   * @param {Uint8Array|String} password
   * @param {Object} [options]
   * @param {Uint8Array} [options.salt]
   *   You should *never* specify the salt manually except for testing purposes
   * @param {Number} [options.opslimit=524288]
   * @param {Number} [options.memlimit=16777216]
   * @param {Function} [callback]
   *   Node-styled callback with 2 arguments: a nullable async error and the
   *   encrypted box
   * @returns {Promise|undefined}
   *   Promise with the encrypted box if the function is called without the callback;
   *   else, nothing
   * @api public
   */
  const pwbox = utils.promisify(_pwbox);

  /**
   * Decrypts a previously encrypted message.
   *
   * @param {Uint8Array|Object} box
   * @param {Uint8Array|String} password
   * @param {Function} [callback]
   *   Node-styled callback with 2 arguments: a nullable async error and the
   *   decrypted message
   * @returns {Promise|undefined}
   *   Promise with the decrypted message if the function is called without the callback;
   *   else, nothing
   * @api public
   */
  pwbox.open = utils.promisify(_pwboxOpen);

  pwbox.overheadLength = serializer.overheadLength;
  pwbox.saltLength = nacl.scrypt.saltLength;
  pwbox.defaultOpslimit = nacl.scrypt.defaultOpslimit;
  pwbox.defaultMemlimit = nacl.scrypt.defaultMemlimit;

  pwbox.orFalse = utils.callBackFalseOnError(pwbox);
  pwbox.open.orFalse = utils.callBackFalseOnError(pwbox.open);

  return pwbox;
};
