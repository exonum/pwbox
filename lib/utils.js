'use strict';

/**
 * Creates a Promise-based version of a function that consumes a callback
 * as the last argument. Quite similar to `promisify` from Bluebird.
 *
 * @param {Function} f function to promisify
 * @returns {Function} promisified function, which supports both old callback
 *   interface, and a new Promise one, depending if the last supplied argument
 *   is a function
 *
 * @api private
 */
exports.promisify = function (f) {
  return function () {
    /*
     * There may be a marginal case where one or more last args are `undefined`.
     * For example, this may occur in this situation:
     *
     * ```
     *   function g (options, callback) {
     *     // Do come manipulations on options
     *     f(options, callback);
     *   }
     *   g({ foo: 'bar'}); // callback is undefined, what can possibly go wrong?
     * ```
     *
     * In this case, we want `f(options, undefined)` to behave in the same way as
     * `f(options)`. That is, `undefined` trailing args should be skipped.
     */
    var argLength = arguments.length;
    while (argLength > 0 && arguments[argLength - 1] === undefined) {
      argLength--;
    }

    var args = Array.prototype.slice.call(arguments, 0, argLength);

    // This assumes that the last argument of the function before the callback
    // is not a function
    if (typeof args[args.length - 1] !== 'function') {
      // Attempt to use promises
      if (typeof Promise !== 'function') {
        throw new Error('No Promise support detected, use callbacks');
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
};

/**
 * Converts a function with a Node-style callback `cb(err, result)` into
 * a function with a single-arg callback `cb(result)`, with `result === false`
 * when an original callback is called with non-null error.
 *
 * @param {Function} f function to convert
 * @returns {Function} converted function
 *
 * @api private
 */
exports.callBackFalseOnError = function (f) {
  return function () {
    var args = Array.prototype.slice.call(arguments);
    if (typeof args[args.length - 1] !== 'function') {
      throw new TypeError('Expected callback as the last argument');
    }

    // Callback interface, need to change the callback
    args[args.length - 1] = (function (cb) {
      return function (err, result) {
        if (err) result = false;
        cb(result);
      };
    })(args[args.length - 1]);

    return f.apply(this, args);
  };
};
