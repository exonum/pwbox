// Karma configuration
module.exports = function (config) {
  config.set({
    basePath: '',
    frameworks: ['browserify', 'mocha'],
    files: [
      'test/test.all.js'
    ],
    exclude: [ ],
    preprocessors: {
      'test/test.all.js': [ 'browserify' ]
    },

    browserify: {
      debug: true,
      transform: [
        [ 'babelify', { presets: [ 'es2015' ], plugins: [ 'istanbul' ] } ]
      ]
    },

    reporters: ['mocha', 'coverage'],
    port: 9876,
    colors: true,
    logLevel: config.LOG_INFO,
    autoWatch: false,
    browsers: ['PhantomJS', 'Firefox'],
    browserNoActivityTimeout: 30000,
    singleRun: true,
    concurrency: Infinity,

    coverageReporter: {
      reporters: [
        {
          type: process.env.CI ? 'lcovonly' : 'lcov',
          dir: 'coverage',
          subdir: function (browser) {
            return browser.toLowerCase().split(/[ /-]/)[0];
          }
        },
        { type: 'text-summary' }
      ]
    }
  });
};
