'use strict';
/* eslint-env node, mocha */

const expect = require('chai')
  .use(require('chai-bytes'))
  .use(require('chai-as-promised'))
  .use(require('dirty-chai'))
  .expect;
const objectAssign = Object.assign || require('object-assign');

const pwbox = require('..');
const sodiumPwbox = pwbox.withCrypto('libsodium');
const cryptoTweetnacl = require('../lib/crypto-tweetnacl');

// low-effort scrypt settings for testing
const TEST_OPTIONS = {
  opslimit: 1 << 16,
  memlimit: 1 << 24
};

// Describes a specific crypto implementation
function describeImplementation (pwbox, cryptoName) {
  describe('pwbox.withCrypto(' + cryptoName + ')', function () {
    this.timeout(0);

    var message = new Uint8Array([ 65, 66, 67 ]);
    var password = 'pleaseletmein';

    // Testing version of `pwbox` with more CPU-friendly options.
    // Used in places where specific values of `opslimit` and `memlimit`
    // don't matter.
    function testBox (options, callback) {
      options = Object.assign({}, TEST_OPTIONS, options);
      return pwbox(message, password, options, callback);
    }

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

    describe('options verification', function () {
      [
        0,
        16,
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
        Math.pow(2, 32),
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
        16,
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
        Math.pow(2, 32),
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

  describe('pwbox.withCrypto(' + cryptoName + ').open', function () {
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

describeImplementation(pwbox, 'tweetnacl');
describeImplementation(sodiumPwbox, 'libsodium');

describe('pwbox compatibility', function () {
  this.timeout(0);

  var message = new Uint8Array([ 65, 66, 67 ]);
  var password = 'pleaseletmein';

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
    { opslimit: pwbox.defaultOpslimit * 4, memlimit: pwbox.defaultMemlimit },
    { opslimit: pwbox.defaultOpslimit * 16, memlimit: pwbox.defaultMemlimit }
  ];

  testVectors.forEach(vector => {
    var opts = objectAssign({
      salt: new Uint8Array(pwbox.saltLength)
    }, vector);

    it('should yield same results on both backends with ' +
      'opslimit = ' + opts.opslimit +
      ', memlimit = ' + opts.memlimit,

      function () {
        this.timeout(10000);

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
