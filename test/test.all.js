if (typeof window !== 'undefined' && !window.Promise) {
  // A (very clumsy) polyfill for PhantomJS
  window.Promise = require('promise');
}

require('./test.constants');
require('./test.serializer');
require('./test.pwbox');
