'use strict';

const chai = require('chai');
const chaiAsPromised = require('chai-as-promised');
chai.use(chaiAsPromised);
const expect = chai.expect;

const pwbox = require('..');
const sodiumPwbox = pwbox.withCrypto('libsodium');
const cryptoTweetnacl = require('../lib/crypto-tweetnacl');

// Describes a specific implementation
function describeImplementation(pwbox, cryptoName) {

describe('pwbox.withCrypto(' + cryptoName + ')', function() {

  var message = new Uint8Array([ 65, 66, 67 ]);
  var password = 'pleaseletmein';

  it('should run with promise and no options', function() {
    var promise = pwbox(message, password);
    expect(promise).to.be.instanceof(Promise);
    expect(promise).to.eventually.be.a('uint8array');
    expect(promise).to.eventually.have.lengthOf(3 + pwbox.overheadLength);
    return promise;
  });

  it('should run with promise and options', function() {
    var promise = pwbox(message, password, {
      opslimit: 1 << 21
    });
    expect(promise).to.be.instanceof(Promise);
    expect(promise).to.eventually.be.a('uint8array');
    expect(promise).to.eventually.have.lengthOf(3 + pwbox.overheadLength);
    return promise;
  });

  it('should run with callback and no options', function(done) {
    var immediateResult = pwbox(message, password, function(result) {
      expect(result).to.be.a('uint8array');
      expect(result).to.have.lengthOf(3 + pwbox.overheadLength);
      done();
    });
    expect(immediateResult).to.be.undefined;
  });

  it('should run with callback and options', function(done) {
    var opts = {
      opslimit: 1 << 21
    };

    var immediateResult = pwbox(message, password, opts, function(result) {
      expect(result).to.be.a('uint8array');
      expect(result).to.have.lengthOf(3 + pwbox.overheadLength);
      done();
    });
    expect(immediateResult).to.be.undefined;
  });

  // TODO test opslimit and memlimit verification
});

describe('pwbox.withCrypto(' + cryptoName + ').open', function() {

  var message = new Uint8Array([ 65, 66, 67 ]);
  var box = new Uint8Array();
  var password = 'pleaseletmein';

  function describeTwoWayOp(testName, message, password) {
    it(testName, function() {
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
    new Uint8Array(100000),
    password);

  describeTwoWayOp(
    'should work with utf-8 passwords',
    message,
    'пуститепожалуйста'
  );
});

} // end of describeImplementation

describeImplementation(pwbox, 'tweetnacl');
describeImplementation(sodiumPwbox, 'libsodium');

describe('pwbox compatibility', function() {

  var message = new Uint8Array([ 65, 66, 67 ]);
  var password = 'pleaseletmein';

  it('should calculate N, r, p adequately for tweetnacl', function() {
    var params = cryptoTweetnacl.scrypt.pickParams(pwbox.defaultOpslimit, pwbox.defaultMemlimit);
    expect(params.log2N).to.equal(14);
    expect(params.r).to.equal(8);
    expect(params.p).to.equal(1);
  });

  // TODO: add test to cover both main branches in pickParams

  it('should yield same results on both backends', function() {
    var opts = {
      salt: new Uint8Array(pwbox.saltLength)
    };

    return Promise.all([
      pwbox(message, password, opts),
      sodiumPwbox(message, password, opts)
    ]).then(results => {
      var tweetBox = results[0], sodiumBox = results[1];
      expect(tweetBox).to.deep.equal(sodiumBox);
    });
  });

  it('should yield same results on both backends with custom memlimit and/or opslimit', function() {
    var testVectors = [
      { opslimit: pwbox.defaultOpslimit / 2 },
      { opslimit: pwbox.defaultOpslimit * 2 },
      { memlimit: pwbox.defaultMemlimit / 2 },
      { memlimit: pwbox.defaultMemlimit * 2 },
      { opslimit: pwbox.defaultOpslimit / 2, memlimit: pwbox.defaultMemlimit * 2 },
      { opslimit: pwbox.defaultOpslimit * 2, memlimit: pwbox.defaultMemlimit / 2 },
    ];

    var jobs = testVectors.map(vector => {
      var opts = Object.assign({
        salt: new Uint8Array(pwbox.saltLength)
      }, vector);

      return Promise.all([
        pwbox(message, password, opts),
        sodiumPwbox(message, password, opts)
      ]).then(results => {
        var tweetBox = results[0], sodiumBox = results[1];
        expect(tweetBox).to.deep.equal(sodiumBox);
        //console.log(tweetBox);
        //console.log(sodiumBox);
      });
    });

    return Promise.all(jobs);
  });
});
