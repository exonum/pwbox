/**
 * @license
 * Copyright 2017 The Exonum Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
'use strict';
/* eslint-env node, mocha */

const expect = require('chai')
  .use(require('chai-bytes'))
  .expect;

const serializer = require('../lib/serializer');

describe('serializer', function () {
  // Serializable object
  var obj = {
    algorithm: {
      id: 'scrypt',
      opslimit: 524288,
      memlimit: 16777216
    },
    salt: new Uint8Array(32),
    ciphertext: new Uint8Array(40)
  };

  for (let i = 0; i < obj.salt.length; i++) {
    obj.salt[i] = i;
  }
  for (let i = 0; i < obj.ciphertext.length; i++) {
    obj.ciphertext[i] = 255 - i;
  }

  describe('serialize', function () {
    it('should serialize into an array of correct size', function () {
      var s = serializer.serialize(obj);
      expect(s).to.be.a('uint8array');
      expect(s).to.have.lengthOf(48 + obj.ciphertext.length);
    });

    it('should throw if algorithm ID contains non-ASCII chars', function () {
      var obj = {
        algorithm: {
          id: 'алго',
          opslimit: 524288,
          memlimit: 16777216
        },
        salt: new Uint8Array(32),
        ciphertext: new Uint8Array(40)
      };

      expect(() => serializer.serialize(obj)).to.throw(Error, /ascii/i);
    });

    it('should serialize algo id with trailing zeros', function () {
      var s = serializer.serialize(obj);
      expect(s.subarray(0, 8)).to.equalBytes([
        115, // s
        99,  // c
        114, // r
        121, // y
        112, // p
        116, // t
        0,   // trailing zeros
        0
      ]);
    });

    it('should serialize opslimit as LE 32-bit value', function () {
      var s = serializer.serialize(obj);
      expect(s.subarray(8, 12)).to.equalBytes('00000800');

      obj.algorithm.opslimit = 129 + (2 << 8) + (255 << 16) + (4 << 24);
      s = serializer.serialize(obj);
      expect(s.subarray(8, 12)).to.equalBytes([129, 2, 255, 4]);
      obj.algorithm.opslimit = 524288; // return to old value
    });

    it('should serialize memlimit as LE 32-bit value', function () {
      var s = serializer.serialize(obj);
      expect(s.subarray(12, 16)).to.equalBytes([0, 0, 0, 1]);

      obj.algorithm.memlimit = 129 + (2 << 8) + (255 << 16) + (4 << 24);
      s = serializer.serialize(obj);
      expect(s.subarray(12, 16)).to.equalBytes([129, 2, 255, 4]);
      obj.algorithm.memlimit = 16777216; // return to old value
    });

    it('should leave salt intact during serialization', function () {
      var s = serializer.serialize(obj);
      expect(s.subarray(16, 48)).to.equalBytes(obj.salt);
    });

    it('should leave ciphertext intact during serialization', function () {
      var s = serializer.serialize(obj);
      expect(s.subarray(48, 88)).to.equalBytes(obj.ciphertext);
    });
  });

  describe('deserialize', function () {
    it('should throw if buffer length is insufficient', function () {
      for (var i = 0; i < serializer.overheadLength; i++) {
        var buffer = new Uint8Array(i);
        expect(function () { serializer.deserialize(buffer); }).to.throw(Error, /insufficient/i);
      }
    });

    it('should deserialize into object with correct structure', function () {
      var buffer = new Uint8Array(100);
      var deser = serializer.deserialize(buffer);
      expect(deser).to.have.property('algorithm');
      expect(deser).to.have.deep.property('algorithm.id');
      expect(deser.algorithm.id).to.be.a('string');
      expect(deser).to.have.deep.property('algorithm.opslimit');
      expect(deser.algorithm.opslimit).to.be.a('number');
      expect(deser).to.have.deep.property('algorithm.memlimit');
      expect(deser.algorithm.memlimit).to.be.a('number');
      expect(deser).to.have.property('salt');
      expect(deser.salt).to.be.a('uint8array');
      expect(deser).to.have.property('ciphertext');
      expect(deser.ciphertext).to.be.a('uint8array');
    });

    it('should remove trailing zeros in algo id', function () {
      var buffer = new Uint8Array(100);
      buffer[0] = 65; // A
      buffer[1] = 66; // B
      buffer[5] = 67; // C, but it is after the first zero

      var deser = serializer.deserialize(buffer);
      expect(deser.algorithm.id).to.equal('AB');
    });

    it('should deserialize algorithm ID without trailing zeros', function () {
      var buffer = new Uint8Array(100);
      buffer.subarray(0, 8).set([65, 66, 67, 68, 69, 70, 71, 72]);
      var deser = serializer.deserialize(buffer);
      expect(deser.algorithm.id).to.equal('ABCDEFGH');
    });
  });
});
