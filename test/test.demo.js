'use strict';
/* eslint-env node,mocha */

const path = require('path');
const sw = require('selenium-webdriver');
const expect = require('chai')
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

  this.slow(500);

  /**
   * Returns a promise that resolves with the specified delay.
   *
   * @param {number} t
   *  resolution delay
   * @returns {Promise<undefined>}
   */
  function wait (t) {
    return new Promise(function (resolve, reject) {
      setTimeout(resolve, t);
    });
  }

  /**
   * Expands the details section on the demo page.
   */
  function openDetails () {
    return saltInput.isDisplayed()
      .then(visible => {
        if (!visible) return detailsLink.click().then(() => wait(500));
      });
  }

  /**
   * Pushes the "Encrypt" button and waits until the encryption is completed.
   */
  function encrypt () {
    return encryptBtn.click()
      .then(() => driver.wait(sw.until.elementIsEnabled(encryptBtn)));
  }

  /**
   * Pushes the "Decrypt" button and waits until the decryption is completed.
   */
  function decrypt () {
    return decryptBtn.click()
      .then(() => driver.wait(sw.until.elementIsEnabled(encryptBtn)));
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
    // Reset main controls
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
      ).to.eventually.equal('' + pwbox.defaultOpslimit);
    });

    it('should set correct default memlimit', function () {
      return expect(
        memlimitInput.getAttribute('value')
      ).to.eventually.equal('' + pwbox.defaultMemlimit);
    });

    it('should reset opslimit', function () {
      return opslimitInput.clear()
        .then(() => opslimitInput.getAttribute('value'))
        .then(value => expect(value).to.equal(''))
        .then(() => driver.findElement({ id: 'opslimit-reset' }))
        .then(elem => elem.click())
        .then(() => opslimitInput.getAttribute('value'))
        .then(value => expect(value).to.equal('' + pwbox.defaultOpslimit));
    });

    it('should reset memlimit', function () {
      return memlimitInput.clear()
        .then(() => memlimitInput.getAttribute('value'))
        .then(value => expect(value).to.equal(''))
        .then(() => driver.findElement({ id: 'memlimit-reset' }))
        .then(elem => elem.click())
        .then(() => memlimitInput.getAttribute('value'))
        .then(value => expect(value).to.equal('' + pwbox.defaultMemlimit));
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

    it('should refuse to encrypt message with small opslimit', function () {
      return expect(opslimitInput.clear()
        .then(() => opslimitInput.sendKeys('32767'))
        .then(encrypt)
        .then(() => driver.findElement({ id: 'encrypt-feedback' }))
        .then(elem => elem.getText())
      ).to.eventually.match(/Error:.*opslimit.*small/i);
    });

    it('should refuse to encrypt message with large opslimit', function () {
      return expect(opslimitInput.clear()
        .then(() => opslimitInput.sendKeys('34000000'))
        .then(encrypt)
        .then(() => driver.findElement({ id: 'encrypt-feedback' }))
        .then(elem => elem.getText())
      ).to.eventually.match(/Error:.*opslimit.*large/i);
    });

    it('should refuse to encrypt message with small memlimit', function () {
      return expect(memlimitInput.clear()
        .then(() => memlimitInput.sendKeys('16500000'))
        .then(encrypt)
        .then(() => driver.findElement({ id: 'encrypt-feedback' }))
        .then(elem => elem.getText())
      ).to.eventually.match(/Error:.*memlimit.*small/i);
    });

    it('should refuse to encrypt message with large memlimit', function () {
      return expect(memlimitInput.clear()
        .then(() => memlimitInput.sendKeys('1100000000'))
        .then(encrypt)
        .then(() => driver.findElement({ id: 'encrypt-feedback' }))
        .then(elem => elem.getText())
      ).to.eventually.match(/Error:.*memlimit.*large/i);
    });

    it('should encrypt message', function () {
      var msg = 'message';

      return expect(Promise.all([
        passwordInput.sendKeys('pleaseletmein'),
        messageInput.sendKeys(msg)
      ]).then(encrypt)
        .then(() => boxInput.getAttribute('value'))
      ).to.eventually.have.lengthOf(2 * (msg.length + pwbox.overheadLength))
        .and.satisfy(box => box.substring(0, 16) === '7363727970740000', 'unexpected algorithm ID')
        .and.satisfy(box => box.substring(16, 24) === '00000800', 'unexpected opslimit')
        .and.satisfy(box => box.substring(24, 32) === '00000001', 'unexpected memlimit');
    });

    it('should return different boxes when called with a non-specific salt', function () {
      var box1, box2;

      return Promise.all([
        passwordInput.sendKeys('pleaseletmein'),
        messageInput.sendKeys('message')
      ]).then(encrypt)
        .then(() => boxInput.getAttribute('value'))
        .then(box => { box1 = box; })
        .then(encrypt)
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
      ]).then(encrypt)
        .then(() => boxInput.getAttribute('value'))
        .then(box => { box1 = box; })
        .then(encrypt)
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
      ]).then(encrypt)
        .then(() => messageInput.clear())
        .then(() => messageInput.getAttribute('value'))
        .then(value => expect(value).to.equal('')) // check that the message has been erased
        .then(decrypt)
        .then(() => messageInput.getAttribute('value'))
        .then(value => expect(value).to.equal(msg));
    });

    it('should decrypt previously encrypted UTF-8 message', function () {
      var msg = 'Пустите, пожалуйста! €';

      return Promise.all([
        passwordInput.sendKeys('pleaseletmein'),
        messageInput.sendKeys(msg)
      ]).then(encrypt)
        .then(() => messageInput.clear())
        .then(() => messageInput.getAttribute('value'))
        .then(value => expect(value).to.equal('')) // check that the message has been erased
        .then(decrypt)
        .then(() => messageInput.getAttribute('value'))
        .then(value => expect(value).to.equal(msg));
    });

    it('should decrypt a message coming from external source', function () {
      var msg = 'Hello, world';
      var password = 'pleaseletmein';

      return pwbox(Buffer.from(msg, 'utf8'), password)
        .then(box => boxInput.sendKeys(Buffer.from(box).toString('hex')))
        .then(() => passwordInput.sendKeys(password))
        .then(decrypt)
        .then(() => messageInput.getAttribute('value'))
        .then(value => expect(value).to.equal(msg));
    });

    it('should fail on incorrect hex box', function () {
      return expect(boxInput.sendKeys('not a hex string')
        .then(decrypt)
        .then(() => driver.findElement({ id: 'decrypt-feedback' }))
        .then(elem => elem.getText())
      ).to.eventually.match(/^Error.*hex/i);
    });

    // Pairs of pwbox mutations and corresponding expected error messages
    var mutations = {
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
      ],

      'small opslimit': [
        function (box) {
          box.subarray(8, 12).set([0, 1, 0, 0]);
          return box;
        },
        /^Error.*opslimit.*small/i
      ],

      'large opslimit': [
        function (box) {
          box.subarray(8, 12).set([255, 255, 255, 255]);
          return box;
        },
        /^Error.*opslimit.*large/i
      ],

      'small memlimit': [
        function (box) {
          box.subarray(12, 16).set([255, 255, 255, 0]);
          return box;
        },
        /^Error.*memlimit.*small/i
      ],

      'large memlimit': [
        function (box) {
          box.subarray(12, 16).set([255, 255, 255, 255]);
          return box;
        },
        /^Error.*memlimit.*large/i
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
          .then(decrypt)
          .then(() => driver.findElement({ id: 'decrypt-feedback' }))
          .then(elem => elem.getText())
        ).to.eventually.match(error);
      });
    }
  });
});
