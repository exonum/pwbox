'use strict';
/* eslint-env node,mocha */

try {
  var sw = require('selenium-webdriver');
} catch (err) {
  console.error('Install `selenium-webdriver` to run tests on demo page');
  throw err;
}

const path = require('path');
const expect = require('chai')
  .use(require('chai-bytes'))
  .use(require('chai-as-promised'))
  .use(require('dirty-chai'))
  .expect;

const pwbox = require('..');

const driver = new sw.Builder()
  .withCapabilities(sw.Capabilities.phantomjs())
  .build();
const DEMO_URL = 'file://' + path.resolve('examples/demo.html');

describe('pwbox demo page', function () {
  var encryptBtn, decryptBtn, passwordInput, messageInput, boxInput, saltInput,
    opslimitInput, memlimitInput, detailsLink;

  function wait (t) {
    return new Promise(function (resolve, reject) {
      setTimeout(resolve, t);
    });
  }

  function openDetails () {
    return saltInput.isDisplayed()
      .then(visible => {
        if (!visible) return detailsLink.click().then(() => wait(500));
      });
  }

  before(function () {
    this.timeout(0);

    return driver.get(DEMO_URL).then(() => {
      return Promise.all([
        driver.findElement({ id: 'encrypt' }).then(elem => { encryptBtn = elem; }),
        driver.findElement({ id: 'decrypt' }).then(elem => { decryptBtn = elem; }),
        driver.findElement({ id: 'password' }).then(elem => { passwordInput = elem; }),
        driver.findElement({ id: 'message' }).then(elem => { messageInput = elem; }),
        driver.findElement({ id: 'box' }).then(elem => { boxInput = elem; }),
        driver.findElement({ id: 'salt' }).then(elem => { saltInput = elem; }),
        driver.findElement({ id: 'opslimit' }).then(elem => { opslimitInput = elem; }),
        driver.findElement({ id: 'memlimit' }).then(elem => { memlimitInput = elem; }),
        driver.findElement({ linkText: 'More options' }).then(elem => { detailsLink = elem; })
      ]).then(openDetails);
    });
  });

  beforeEach(function () {
    // Reset all controls
    return Promise.all([
      passwordInput.clear(),
      messageInput.clear(),
      boxInput.clear(),
      saltInput.clear()
    ]);
  });

  describe('basic operations', function () {
    it('should set correct default opslimit', function () {
      return expect(
        opslimitInput.getAttribute('value')
      ).to.eventually.equal('524288');
    });

    it('should set correct default memlimit', function () {
      return expect(
        memlimitInput.getAttribute('value')
      ).to.eventually.equal('16777216');
    });

    it('should reset opslimit', function () {
      return opslimitInput.clear()
        .then(() => opslimitInput.getAttribute('value'))
        .then(value => expect(value).to.equal(''))
        .then(() => driver.findElement({ id: 'opslimit-reset' }))
        .then(elem => elem.click())
        .then(() => opslimitInput.getAttribute('value'))
        .then(value => expect(value).to.equal('524288'));
    });

    it('should reset memlimit', function () {
      return memlimitInput.clear()
        .then(() => memlimitInput.getAttribute('value'))
        .then(value => expect(value).to.equal(''))
        .then(() => driver.findElement({ id: 'memlimit-reset' }))
        .then(elem => elem.click())
        .then(() => memlimitInput.getAttribute('value'))
        .then(value => expect(value).to.equal('16777216'));
    });

    function generateSalt () {
      return openDetails()
        .then(() => driver.findElement({ id: 'salt-random' }))
        .then(el => el.click())
        .then(() => saltInput.getAttribute('value'));
    }

    it('should generate salt', function () {
      return expect(generateSalt())
        .to.eventually.have.lengthOf(2 * pwbox.saltLength)
        .and.match(/^[0-9a-f]+$/);
    });

    it('should generate a different salt each time', function () {
      var salt1, salt2;

      return expect(generateSalt()
        .then(salt => { salt1 = salt; })
        .then(() => generateSalt())
        .then(salt => { salt2 = salt; })
        .then(() => [salt1, salt2])
      ).to.eventually.satisfy(salts => salts[0] !== salts[1], 'random salts are not random at all!');
    });
  });

  describe('encryption', function () {
    beforeEach(function () {
      // Reset opslimit and memlimit
      return Promise.all([
        driver.findElement({ id: 'opslimit-reset' }).then(elem => elem.click()),
        driver.findElement({ id: 'memlimit-reset' }).then(elem => elem.click())
      ]);
    });

    it('should encrypt message', function () {
      var msg = 'message';

      return expect(Promise.all([
        passwordInput.sendKeys('pleaseletmein'),
        messageInput.sendKeys(msg)
      ]).then(() => {
        return encryptBtn.click();
      }).then(() => {
        return boxInput.getAttribute('value');
      })).to.eventually.have.lengthOf(2 * (msg.length + pwbox.overheadLength))
        .and.satisfy(box => box.substring(0, 16) === '7363727970740000', 'unexpected algorithm ID')
        .and.satisfy(box => box.substring(16, 24) === '00000800', 'unexpected opslimit')
        .and.satisfy(box => box.substring(24, 32) === '00000001', 'unexpected memlimit');
    });

    it('should return different boxes when called with a non-specific salt', function () {
      var box1, box2;

      return Promise.all([
        passwordInput.sendKeys('pleaseletmein'),
        messageInput.sendKeys('message')
      ]).then(() => encryptBtn.click())
        .then(() => boxInput.getAttribute('value'))
        .then(box => { box1 = box; })
        .then(() => encryptBtn.click())
        .then(() => boxInput.getAttribute('value'))
        .then(box => { box2 = box; })
        .then(() => expect(box2).to.not.equal(box1));
    });

    it('should return consistent box when called with a predefined salt', function () {
      var zeroSalt = '';
      for (var i = 0; i < 2 * pwbox.saltLength; i++) zeroSalt += '0';

      var box1, box2;

      return Promise.all([
        passwordInput.sendKeys('pleaseletmein'),
        messageInput.sendKeys('message'),
        saltInput.sendKeys(zeroSalt)
      ]).then(() => encryptBtn.click())
        .then(() => boxInput.getAttribute('value'))
        .then(box => { box1 = box; })
        .then(() => encryptBtn.click())
        .then(() => boxInput.getAttribute('value'))
        .then(box => { box2 = box; })
        .then(() => expect(box2).to.equal(box1));
    });
  });

  describe('decryption', function () {
    beforeEach(function () {
      // Reset opslimit and memlimit
      return Promise.all([
        driver.findElement({ id: 'opslimit-reset' }).then(elem => elem.click()),
        driver.findElement({ id: 'memlimit-reset' }).then(elem => elem.click())
      ]);
    });

    it('should decrypt previously encrypted message', function () {
      var msg = 'message';

      return Promise.all([
        passwordInput.sendKeys('pleaseletmein'),
        messageInput.sendKeys(msg)
      ]).then(() => encryptBtn.click())
        .then(() => messageInput.clear())
        .then(() => messageInput.getAttribute('value'))
        .then(value => expect(value).to.equal('')) // check that the message has been erased
        .then(() => decryptBtn.click())
        .then(() => messageInput.getAttribute('value'))
        .then(value => expect(value).to.equal(msg));
    });

    it('should decrypt previously encrypted UTF-8 message', function () {
      var msg = 'Пустите, пожалуйста! €';

      return Promise.all([
        passwordInput.sendKeys('pleaseletmein'),
        messageInput.sendKeys(msg)
      ]).then(() => encryptBtn.click())
        .then(() => messageInput.clear())
        .then(() => messageInput.getAttribute('value'))
        .then(value => expect(value).to.equal('')) // check that the message has been erased
        .then(() => decryptBtn.click())
        .then(() => messageInput.getAttribute('value'))
        .then(value => expect(value).to.equal(msg));
    });

    it('should decrypt a message coming from external source', function () {
      var msg = 'Hello, world';
      var password = 'pleaseletmein';

      return pwbox(Buffer.from(msg, 'utf8'), password)
        .then(box => boxInput.sendKeys(Buffer.from(box).toString('hex')))
        .then(() => passwordInput.sendKeys(password))
        .then(() => decryptBtn.click())
        .then(() => messageInput.getAttribute('value'))
        .then(value => expect(value).to.equal(msg));
    });

    it('should fail on incorrect hex box', function () {
      return expect(boxInput.sendKeys('not a hex string')
        .then(() => decryptBtn.click())
        .then(() => driver.findElement({ id: 'decrypt-feedback' }))
        .then(elem => elem.getText())
      ).to.eventually.match(/^Error.*hex/i);
    });

    // Pairs of pwbox mutations and corresponding expected error messages
    var mutations = {
      // TODO: add opslimit and memlimit corruptions

      'invalid algorithm': [
        function (box) {
          box[0] = 32;
          return box;
        },
        /^Error.*algorithm/i
      ],
      'corrupted box': [
        function (box) {
          box[pwbox.overheadLength + 1]++;
          return box;
        },
        /^Error.*corrupted/i
      ],
      'shortened box': [
        function (box) {
          return box.slice(0, box.length - 1);
        },
        /^Error.*corrupted/i
      ],
      'stretched box': [
        function (box) {
          var stretched = new Uint8Array(box.length + 1);
          stretched.set(box);
          return stretched;
        },
        /^Error.*corrupted/i
      ]
    };

    for (var name in mutations) {
      let mutation = mutations[name][0];
      let error = mutations[name][1];

      it('should fail on ' + name, function () {
        var msg = 'Hello, world';
        var password = 'pleaseletmein';

        return expect(pwbox(Buffer.from(msg, 'utf8'), password)
          .then(box => {
            box = mutation(box);
            return Buffer.from(box).toString('hex');
          })
          .then(box => boxInput.sendKeys(box))
          .then(() => passwordInput.sendKeys(password))
          .then(() => decryptBtn.click())
          .then(() => driver.findElement({ id: 'decrypt-feedback' }))
          .then(elem => elem.getText())
        ).to.eventually.match(error);
      });
    }
  });
});
