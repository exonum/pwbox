module.exports = {
  promisify: function (f) {
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
  },

  callBackFalseOnError: function (f) {
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
  }
};
