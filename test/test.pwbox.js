'use strict';
/* eslint-env node, mocha */

const chai = require('chai');
chai.use(require('chai-as-promised'));
chai.use(require('dirty-chai'));
const expect = chai.expect;

const pwbox = require('..');
const sodiumPwbox = pwbox.withCrypto('libsodium');
const cryptoTweetnacl = require('../lib/crypto-tweetnacl');

// Describes a specific crypto implementation
function describeImplementation (pwbox, cryptoName) {
  describe('pwbox.withCrypto(' + cryptoName + ')', function () {
    var message = new Uint8Array([ 65, 66, 67 ]);
    var password = 'pleaseletmein';

    it('should run with promise and no options', function () {
      var promise = pwbox(message, password);
      expect(promise).to.be.instanceof(Promise);
      expect(promise).to.eventually.be.a('uint8array');
      expect(promise).to.eventually.have.lengthOf(3 + pwbox.overheadLength);
      return promise;
    });

    it('should run with promise and options', function () {
      var promise = pwbox(message, password, {
        opslimit: 1 << 21
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
        opslimit: 1 << 21
      };

      var immediateResult = pwbox(message, password, opts, function (err, result) {
        expect(err).to.not.exist();
        expect(result).to.be.a('uint8array');
        expect(result).to.have.lengthOf(3 + pwbox.overheadLength);
        done();
      });
      expect(immediateResult).to.be.undefined();
    });

    // TODO test opslimit and memlimit verification
  });

  describe('pwbox.withCrypto(' + cryptoName + ').open', function () {
    var message = new Uint8Array([ 65, 66, 67 ]);
    var box = new Uint8Array(); // initialized in `before`
    var corruptedBox = new Uint8Array();
    var invalidAlgoBox = new Uint8Array();
    var password = 'pleaseletmein';

    before(function () {
      return pwbox(message, password, {
        salt: new Uint8Array(pwbox.saltLength)
      }).then(b => {
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

    function describeTwoWayOp (testName, message, password) {
      it(testName, function () {
        var promise = pwbox(message, password).then(box => {
          return pwbox.open(box, password);
        });
        expect(promise).to.eventually.deep.equal(message);
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
  });
}

describeImplementation(pwbox, 'tweetnacl');
describeImplementation(sodiumPwbox, 'libsodium');

describe('pwbox compatibility', function () {
  var message = new Uint8Array([ 65, 66, 67 ]);
  var password = 'pleaseletmein';

  it('should calculate N, r, p adequately for tweetnacl', function () {
    var params = cryptoTweetnacl.scrypt.pickParams(pwbox.defaultOpslimit, pwbox.defaultMemlimit);
    expect(params.log2N).to.equal(14);
    expect(params.r).to.equal(8);
    expect(params.p).to.equal(1);
  });

  // TODO: add test to cover both main branches in pickParams

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
      expect(tweetBox).to.deep.equal(sodiumBox);
    });
  });

  var testVectors = [
    { opslimit: pwbox.defaultOpslimit / 2 },
    { opslimit: pwbox.defaultOpslimit * 2 },
    { memlimit: pwbox.defaultMemlimit / 2 },
    { memlimit: pwbox.defaultMemlimit * 2 },
    { opslimit: pwbox.defaultOpslimit / 2, memlimit: pwbox.defaultMemlimit * 2 },
    { opslimit: pwbox.defaultOpslimit * 2, memlimit: pwbox.defaultMemlimit / 2 }
  ];

  testVectors.forEach(vector => {
    var opts = Object.assign({
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
          expect(tweetBox).to.deep.equal(sodiumBox);
        });
      });
  });
});
