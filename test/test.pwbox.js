'use strict';
/* eslint-env node, mocha */

const expect = require('chai')
  .use(require('chai-bytes'))
  .use(require('sinon-chai'))
  .use(require('chai-as-promised'))
  .use(require('dirty-chai'))
  .expect;
const sinon = require('sinon');
const objectAssign = Object.assign || require('object-assign');

const pwbox = require('..');
const sodiumPwbox = pwbox.withCrypto('libsodium');
const litePwbox = require('../lite');
const cryptoTweetnacl = require('../lib/crypto-tweetnacl');

// low-effort scrypt settings for testing
const TEST_OPTIONS = {
  opslimit: 1 << 16,
  memlimit: 1 << 24
};

// Describes a specific crypto implementation
function describeImplementation (pwbox, pwboxName) {
  describe(pwboxName, function () {
    this.timeout(0);

    var message = new Uint8Array([ 65, 66, 67 ]);
    var password = 'pleaseletmein';

    // Testing version of `pwbox` with more CPU-friendly options.
    // Used in places where specific values of `opslimit` and `memlimit`
    // don't matter.
    function testBox (options, callback) {
      options = objectAssign({}, TEST_OPTIONS, options);
      return pwbox(message, password, options, callback);
    }

    it('should throw when called with promise and Promise isn\'t present', function () {
      var _Promise = Promise;
      try {
        delete global.Promise;
        expect(typeof Promise).to.equal('undefined', 'Cannot delete Promise');
        expect(() => pwbox(message, password)).to.throw(Error, /Promise/i);
      } finally {
        global.Promise = _Promise;
      }
    });

    it('should run with promise and no options', function () {
      var promise = pwbox(message, password);
      expect(promise).to.be.instanceof(Promise);
      expect(promise).to.eventually.be.a('uint8array');
      expect(promise).to.eventually.have.lengthOf(3 + pwbox.overheadLength);
      return promise;
    });

    it('should run with promise and options', function () {
      var promise = pwbox(message, password, {
        opslimit: 1 << 17
      });
      expect(promise).to.be.instanceof(Promise);
      expect(promise).to.eventually.be.a('uint8array');
      expect(promise).to.eventually.have.lengthOf(3 + pwbox.overheadLength);
      return promise;
    });

    it('should run with callback and no options', function (done) {
      var immediateResult = pwbox(message, password, function (err, result) {
        expect(err).to.not.exist();
        expect(result).to.be.a('uint8array');
        expect(result).to.have.lengthOf(3 + pwbox.overheadLength);
        done();
      });
      expect(immediateResult).to.be.undefined();
    });

    it('should run with callback and options', function (done) {
      var opts = {
        opslimit: 1 << 17
      };

      var immediateResult = pwbox(message, password, opts, function (err, result) {
        expect(err).to.not.exist();
        expect(result).to.be.a('uint8array');
        expect(result).to.have.lengthOf(3 + pwbox.overheadLength);
        done();
      });
      expect(immediateResult).to.be.undefined();
    });

    // See more about Zalgo here: http://blog.izs.me/post/59142742143/designing-apis-for-asynchrony
    it('should not release Zalgo', function (done) {
      var after = false;
      testBox({}, function (err, result) {
        expect(err).to.not.exist();
        expect(after).to.be.true();
        done();
      });
      after = true;
    });

    describe('constants', function () {
      [
        'saltLength',
        'overheadLength',
        'defaultOpslimit',
        'defaultMemlimit',
        'minOpslimit',
        'minMemlimit',
        'maxOpslimit',
        'maxMemlimit'
      ].forEach(c => {
        it('should define constant ' + c, function () {
          expect(pwbox[c]).to.be.a('number');
        });
      });
    });

    describe('options verification', function () {
      [
        0,
        1024,
        (1 << 15) - 1 // The minimum allowed value is 1 << 15 (32768)
      ].forEach(ops => {
        it('should disallow small opslimit value ' + ops + ' in promise form', function () {
          expect(testBox({ opslimit: ops })).to.be.rejectedWith(RangeError, /opslimit/i);
        });

        it('should disallow small opslimit value ' + ops + ' in callback form', function () {
          expect(() => testBox({ opslimit: ops }, () => {})).to.throw(RangeError, /opslimit/i);
        });
      });

      [
        (1 << 25) + 1, // the maximum allowed value is 1 << 25 (32M)
        Math.pow(2, 52) // close to max safe integer value in JS
      ].forEach(ops => {
        it('should disallow large opslimit value ' + ops + ' in promise form', function () {
          expect(testBox({ opslimit: ops })).to.be.rejectedWith(RangeError, /opslimit/i);
        });

        it('should disallow large opslimit value ' + ops + ' in callback form', function () {
          expect(() => testBox({ opslimit: ops }, () => {})).to.throw(RangeError, /opslimit/i);
        });
      });

      [
        0,
        1024,
        (1 << 24) - 1 // The minimum allowed value is 1 << 24 (16M)
      ].forEach(mem => {
        it('should disallow small memlimit value ' + mem + ' in promise form', function () {
          expect(testBox({ memlimit: mem })).to.be.rejectedWith(RangeError, /memlimit/i);
        });

        it('should disallow small memlimit value ' + mem + ' in callback form', function () {
          expect(() => testBox({ memlimit: mem }, () => {})).to.throw(RangeError, /memlimit/i);
        });
      });

      [
        (1 << 30) + 1, // The maximum allowed value is 1 << 30 (1G)
        Math.pow(2, 52) // close to max safe integer value in JS
      ].forEach(mem => {
        it('should disallow large memlimit value ' + mem + ' in promise form', function () {
          expect(testBox({ memlimit: mem })).to.be.rejectedWith(RangeError, /memlimit/i);
        });

        it('should disallow large memlimit value ' + mem + ' in callback form', function () {
          expect(() => testBox({ memlimit: mem }, () => {})).to.throw(RangeError, /memlimit/i);
        });
      });
    });

    describe('object encoding', function () {
      it('should detect disallowed encoding value in promise form', function () {
        expect(testBox({ encoding: 'none' })).to.be.rejectedWith(TypeError, /encoding/i);
      });

      it('should detect disallowed encoding value in callback form', function () {
        expect(() => testBox({ encoding: 'none' }, () => {})).to.throw(TypeError, /encoding/i);
      });

      it('should return object when called with object encoding', function () {
        return testBox({ encoding: 'object' }).then(obj => {
          expect(obj).to.be.an('object');
          expect(obj.algorithm.id).to.equal('scrypt');
          expect(obj.algorithm.opslimit).to.equal(TEST_OPTIONS.opslimit);
          expect(obj.algorithm.memlimit).to.equal(TEST_OPTIONS.memlimit);
          expect(obj.salt).to.be.a('uint8array').with.lengthOf(pwbox.saltLength);
          expect(obj.ciphertext).to.be.a('uint8array').with.lengthOf(16 + message.length);
        });
      });
    });

    describe('orFalse', function () {
      it('should return result as the first argument in callback', function (done) {
        pwbox.orFalse(message, password, TEST_OPTIONS, function (result) {
          expect(result).to.be.a('uint8array');
          done();
        });
      });

      it('should not accept non-callback interface', function () {
        expect(() => { pwbox.orFalse(message, password); })
          .to.throw(TypeError);
      });
    });
  });

  describe(pwboxName + '.open', function () {
    this.timeout(0);

    var message = new Uint8Array([ 65, 66, 67 ]);
    var box = new Uint8Array(); // initialized in `before`
    var corruptedBox = new Uint8Array();
    var invalidAlgoBox = new Uint8Array();
    var password = 'pleaseletmein';

    before(function () {
      return pwbox(message, password, objectAssign({}, TEST_OPTIONS, {
        salt: new Uint8Array(pwbox.saltLength)
      })).then(b => {
        box = b;
        corruptedBox = new Uint8Array(box);
        corruptedBox[pwbox.overheadLength + 1] = 255 - corruptedBox[pwbox.overheadLength + 1];
        invalidAlgoBox = new Uint8Array(box);
        invalidAlgoBox[0] = 20;
      });
    });

    it('should fail on incorrect algo id with promise', function () {
      var opened = pwbox.open(invalidAlgoBox, password);
      return expect(opened).to.be.rejectedWith(Error, /algorithm/i);
    });

    it('should fail on incorrect algo id with callback', function (done) {
      pwbox.open(invalidAlgoBox, password, (err, opened) => {
        expect(err).to.be.instanceof(Error);
        expect(err.message).to.match(/algorithm/i);
        done();
      });
    });

    it('should fail on incorrect algo id with object box', function () {
      var boxObj = {
        algorithm: {
          id: 'lol',
          opslimit: TEST_OPTIONS.opslimit,
          memlimit: TEST_OPTIONS.memlimit
        },
        salt: new Uint8Array(pwbox.saltLength),
        ciphertext: box.subarray(16 + pwbox.saltLength)
      };
      return expect(pwbox.open(boxObj, password)).to.be.rejectedWith(Error, /algorithm/i);
    });

    it('should fail on corrupted input with promise', function () {
      var opened = pwbox.open(corruptedBox, password);
      return expect(opened).to.be.rejectedWith(Error, /corrupted/i);
    });

    it('should fail on corrupted input with callback', function (done) {
      pwbox.open(corruptedBox, password, (err, opened) => {
        expect(err).to.be.instanceof(Error);
        expect(err.message).to.match(/corrupted/i);
        done();
      });
    });

    it('should fail on corrupted input with object box', function () {
      var corruptedObj = {
        algorithm: {
          id: 'scrypt',
          opslimit: TEST_OPTIONS.opslimit,
          memlimit: TEST_OPTIONS.memlimit
        },
        salt: new Uint8Array(pwbox.saltLength),
        ciphertext: corruptedBox.subarray(16 + pwbox.saltLength)
      };
      return expect(pwbox.open(corruptedObj, password)).to.be.rejectedWith(Error, /corrupted/i);
    });

    it('should fail on input with too small opslimit', function () {
      var boundsBox = new Uint8Array(box);
      var opslimitBytes = boundsBox.subarray(8, 12);
      opslimitBytes.set([ 0, 4, 0, 0 ]); // 1024
      var opened = pwbox.open(boundsBox, password);
      return expect(opened).to.be.rejectedWith(RangeError, /opslimit/i);
    });

    it('should fail on input with too large opslimit', function () {
      var boundsBox = new Uint8Array(box);
      var opslimitBytes = boundsBox.subarray(8, 12);
      opslimitBytes.set([ 0, 0, 0, 4 ]); // 64M, 2x the max limit
      var opened = pwbox.open(boundsBox, password);
      return expect(opened).to.be.rejectedWith(RangeError, /opslimit/i);
    });

    it('should fail on input with too small memlimit', function () {
      var boundsBox = new Uint8Array(box);
      var memlimitBytes = boundsBox.subarray(12, 16);
      memlimitBytes.set([ 0, 0, 128, 0 ]); // 8M
      var opened = pwbox.open(boundsBox, password);
      return expect(opened).to.be.rejectedWith(RangeError, /memlimit/i);
    });

    it('should fail on input with too large memlimit', function () {
      var boundsBox = new Uint8Array(box);
      var memlimitBytes = boundsBox.subarray(12, 16);
      memlimitBytes.set([ 1, 0, 0, 64 ]); // max limit + 1
      var opened = pwbox.open(boundsBox, password);
      return expect(opened).to.be.rejectedWith(RangeError, /memlimit/i);
    });

    it('should not release Zalgo', function (done) {
      var after = false;
      pwbox.open(box, password, function (err, result) {
        expect(err).to.not.exist();
        expect(after).to.be.true();
        done();
      });
      after = true;
    });

    it('should not release Zalgo if supplied with invalid algo id', function (done) {
      var after = false;
      pwbox.open(invalidAlgoBox, password, function (err, result) {
        expect(err).to.be.instanceof(Error);
        expect(after).to.be.true();
        done();
      });
      after = true;
    });

    it('should not release Zalgo if supplied with corrupted box', function (done) {
      var after = false;
      pwbox.open(corruptedBox, password, function (err, result) {
        expect(err).to.be.instanceof(Error);
        expect(after).to.be.true();
        done();
      });
      after = true;
    });

    it('should work with object box', function () {
      var boxObj = {
        algorithm: {
          id: 'scrypt',
          opslimit: TEST_OPTIONS.opslimit,
          memlimit: TEST_OPTIONS.memlimit
        },
        salt: new Uint8Array(pwbox.saltLength),
        ciphertext: box.subarray(16 + pwbox.saltLength)
      };
      var promise = pwbox.open(boxObj, password);
      expect(promise).to.eventually.equalBytes(message);
      return promise;
    });

    function describeTwoWayOp (testName, message, password) {
      it(testName, function () {
        var promise = pwbox(message, password, TEST_OPTIONS).then(box => {
          return pwbox.open(box, password);
        });
        expect(promise).to.eventually.equalBytes(message);
        return promise;
      });
    }

    describeTwoWayOp(
      'should open sealed box',
      message,
      password);

    describeTwoWayOp(
      'should work with long passwords',
      message,
      'correct horse battery staple correct horse battery staple correct horse battery staple correct horse battery staple');

    describeTwoWayOp(
      'should work with long messages',
      new Uint8Array(10000),
      password);

    describeTwoWayOp(
      'should work with utf-8 passwords',
      message,
      'пуститепожалуйста'
    );

    describe('orFalse', function () {
      it('should return false on error', function (done) {
        pwbox.open.orFalse(corruptedBox, password, function (result) {
          expect(result).to.be.false();
          done();
        });
      });

      it('should return result as the first argument in callback', function (done) {
        pwbox.open.orFalse(box, password, function (result) {
          expect(result).to.be.equalBytes(message);
          done();
        });
      });

      it('should not accept non-callback interface', function () {
        expect(() => { pwbox.open.orFalse(box, password); })
          .to.throw(TypeError);
      });
    });
  });
}

describeImplementation(pwbox, 'pwbox');
describeImplementation(sodiumPwbox, 'pwbox.withCrypto(\'libsodium\')');
describeImplementation(litePwbox, 'pwbox/lite');

describe('withCrypto', function () {
  // Use a non-trivial derived key to test key/nonce distribution for `secretbox`
  const DERIVED_KEY = new Uint8Array(56);
  for (var i = 0; i < DERIVED_KEY.length; i++) {
    DERIVED_KEY[i] = i;
  }

  var mockCrypto = {
    scrypt: function (password, salt, options, callback) {
      setTimeout(() => {
        callback(DERIVED_KEY);
      }, 20);
    },

    randomBytes: function (len) {
      return new Uint8Array(len);
    },

    secretbox: function (message, nonce, key) {
      return new Uint8Array(16 + message.length);
    }
  };

  mockCrypto.secretbox.open = function (box, nonce, key) {
    return new Uint8Array(box.length - 16);
  };

  var customPwbox;
  var message = new Uint8Array([ 65, 66, 67 ]);
  var password = 'pleaseletmein';

  var box;

  before(function () {
    // Box needs to look legitimate for it not to trigger error checks
    return pwbox(message, password, TEST_OPTIONS).then(b => { box = b; });
  });

  beforeEach(function () {
    sinon.spy(mockCrypto, 'scrypt');
    sinon.spy(mockCrypto, 'secretbox');
    sinon.spy(mockCrypto, 'randomBytes');
    sinon.spy(mockCrypto.secretbox, 'open');

    customPwbox = pwbox.withCrypto(mockCrypto);
  });

  afterEach(function () {
    mockCrypto.scrypt.restore();
    mockCrypto.secretbox.restore();
    mockCrypto.randomBytes.restore();
  });

  it('should call scrypt on pwbox call', function () {
    return customPwbox(message, password).then(() => {
      expect(mockCrypto.scrypt).to.have.been.calledOnce()
        .and.calledWith(password, new Uint8Array(32) /* salt */);

      var call = mockCrypto.scrypt.getCall(0);
      var options = call.args[2];
      expect(options.dkLength).to.equal(32 + 24);
      expect(options.opslimit).to.equal(pwbox.defaultOpslimit);
      expect(options.memlimit).to.equal(pwbox.defaultMemlimit);

      var cb = call.args[3];
      expect(cb).to.be.a('function');
    });
  });

  it('should call scrypt on pwbox.open call', function () {
    return customPwbox.open(box, password).then(() => {
      expect(mockCrypto.scrypt).to.have.been.calledOnce()
        .and.calledWith(password, box.subarray(16, 48) /* salt */);

      var call = mockCrypto.scrypt.getCall(0);
      var options = call.args[2];
      expect(options.dkLength).to.equal(32 + 24);
      expect(options.opslimit).to.equal(TEST_OPTIONS.opslimit);
      expect(options.memlimit).to.equal(TEST_OPTIONS.memlimit);

      var cb = call.args[3];
      expect(cb).to.be.a('function');
    });
  });

  it('should call secretbox on pwbox call', function () {
    var key = DERIVED_KEY.subarray(0, 32);
    var nonce = DERIVED_KEY.subarray(32);

    return customPwbox(message, password).then(() => {
      expect(mockCrypto.secretbox).to.have.been.calledOnce()
        .and.calledWithExactly(message, nonce, key);
    });
  });

  it('should call secretbox.open on pwbox.open call', function () {
    var key = DERIVED_KEY.subarray(0, 32);
    var nonce = DERIVED_KEY.subarray(32);

    return customPwbox.open(box, password).then(() => {
      expect(mockCrypto.secretbox.open).to.have.been.calledOnce()
        .and.calledWithExactly(box.subarray(16 + 32), nonce, key);
    });
  });

  it('should call scrypt with custom opslimit and memlimit', function () {
    return customPwbox(message, password, { opslimit: 1 << 20, memlimit: 1 << 25 }).then(() => {
      expect(mockCrypto.scrypt).to.have.been.calledOnce();

      var call = mockCrypto.scrypt.getCall(0);
      var options = call.args[2];
      expect(options.opslimit).to.equal(1 << 20);
      expect(options.memlimit).to.equal(1 << 25);
    });
  });

  [
    [ { opslimit: (1 << 15) - 1 }, 'small opslimit' ],
    [ { opslimit: (1 << 25) + 1 }, 'large opslimit' ],
    [ { memlimit: (1 << 24) - 1 }, 'small memlimit' ],
    [ { memlimit: (1 << 30) + 1 }, 'large memlimit' ],
    [ { encoding: 'none' }, 'invalid encoding' ]
  ].forEach(vector => {
    var options = vector[0];
    var name = vector[1];

    it('should not call scrypt or secretbox on calling pwbox with ' + name, function () {
      return expect(customPwbox(message, password, options)).to.have.been.rejected()
        .then(() => {
          expect(mockCrypto.scrypt).to.not.have.been.called();
          expect(mockCrypto.secretbox).to.not.have.been.called();
        });
    });
  });

  [
    [ box => box.subarray(8, 12).set([0xff, 0x7f, 0, 0]), 'small opslimit' ],
    [ box => box.subarray(8, 12).set([1, 0, 0, 2]), 'large opslimit' ],
    [ box => box.subarray(12, 16).set([0xff, 0xff, 0xff, 0]), 'small memlimit' ],
    [ box => box.subarray(12, 16).set([1, 0, 0, 0x40]), 'large memlimit' ],
    [ box => { box[0] = 32; }, 'invalid algo id' ]
  ].forEach(vector => {
    let mutation = vector[0];
    var name = vector[1];

    it('should not call scrypt or secretbox on calling pwbox.open with ' + name, function () {
      var corruptedBox = new Uint8Array(box);
      mutation(corruptedBox);

      return expect(customPwbox.open(corruptedBox, password)).to.have.been.rejected()
        .then(() => {
          expect(mockCrypto.scrypt).to.not.have.been.called();
          expect(mockCrypto.secretbox).to.not.have.been.called();
        });
    });
  });

  it('should yield expected result', function () {
    return customPwbox(message, password).then(box => {
      expect(box).to.be.a('uint8array').and
        .have.lengthOf(message.length + pwbox.overheadLength);
      expect(box.subarray(16)).to.equalBytes(new Uint8Array(box.length - 16));
    });
  });

  it('should yield expected result for object encoding', function () {
    return customPwbox(message, password, { encoding: 'object' }).then(box => {
      expect(box).to.be.an('object');
      expect(box.algorithm.id).to.equal('scrypt');
      expect(box.algorithm.opslimit).to.equal(pwbox.defaultOpslimit);
      expect(box.algorithm.memlimit).to.equal(pwbox.defaultMemlimit);
      expect(box.salt).to.equalBytes(new Uint8Array(pwbox.saltLength));
      expect(box.ciphertext).to.equalBytes(new Uint8Array(16 + message.length));
    });
  });

  it('should call randomBytes on pwbox call to generate salt', function () {
    return customPwbox(message, password).then(() => {
      expect(mockCrypto.randomBytes).to.have.been.calledOnce()
        .and.calledWithExactly(pwbox.saltLength);
    });
  });

  it('should not call randomBytes on pwbox call if salt is predefined', function () {
    return customPwbox(message, password, { salt: new Uint8Array(32) }).then(() => {
      expect(mockCrypto.randomBytes).to.not.have.been.called();
    });
  });
});

describe('pwbox compatibility', function () {
  this.timeout(0);

  var message = new Uint8Array([ 65, 66, 67 ]);
  var password = 'pleaseletmein';
  var utf8Password = 'пожалуйста пустите!';

  it('should calculate N, r, p adequately for tweetnacl', function () {
    var params = cryptoTweetnacl.scrypt.pickParams(pwbox.defaultOpslimit, pwbox.defaultMemlimit);
    expect(params.log2N).to.equal(14);
    expect(params.r).to.equal(8);
    expect(params.p).to.equal(1);
  });

  it('should yield same results on both backends', function () {
    var opts = {
      salt: new Uint8Array(pwbox.saltLength)
    };

    return Promise.all([
      pwbox(message, password, opts),
      sodiumPwbox(message, password, opts)
    ]).then(results => {
      var tweetBox = results[0];
      var sodiumBox = results[1];
      expect(tweetBox).to.equalBytes(sodiumBox);
    });
  });

  // The default memory limit is the minimal one, so there are no tests with lower values
  var testVectors = [
    { opslimit: pwbox.defaultOpslimit / 8 },
    { opslimit: pwbox.defaultOpslimit / 2 },
    { opslimit: pwbox.defaultOpslimit * 2 },
    { memlimit: pwbox.defaultMemlimit * 2 },
    { opslimit: pwbox.defaultOpslimit / 8, memlimit: pwbox.defaultMemlimit * 4 },
    { opslimit: pwbox.defaultOpslimit / 2, memlimit: pwbox.defaultMemlimit * 4 },
    { opslimit: pwbox.defaultOpslimit * 4, memlimit: pwbox.defaultMemlimit * 2 },
    { opslimit: pwbox.defaultOpslimit * 16, memlimit: pwbox.defaultMemlimit }
  ];

  it('should yield same results on both backends with utf-8 password', function () {
    var opts = { salt: new Uint8Array(pwbox.saltLength) };

    return Promise.all([
      pwbox(message, utf8Password, opts),
      sodiumPwbox(message, utf8Password, opts)
    ]).then(results => {
      var tweetBox = results[0];
      var sodiumBox = results[1];
      expect(tweetBox).to.equalBytes(sodiumBox);
    });
  });

  testVectors.forEach(vector => {
    var opts = objectAssign({
      salt: new Uint8Array(pwbox.saltLength)
    }, vector);

    it('should yield same results on both backends with ' +
      'opslimit = ' + opts.opslimit +
      ', memlimit = ' + opts.memlimit,

      function () {
        return Promise.all([
          pwbox(message, password, opts),
          sodiumPwbox(message, password, opts)
        ]).then(results => {
          var tweetBox = results[0];
          var sodiumBox = results[1];
          expect(tweetBox).to.equalBytes(sodiumBox);
        });
      });
  });
});
