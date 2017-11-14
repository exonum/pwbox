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

const constants = require('./crypto-constants');

const constLength = 8 + // algorithm id
  4 + // memlimit
  4 + // opslimit
  constants.scrypt.saltLength; // salt

const overheadLength = exports.overheadLength = constLength + constants.secretbox.overheadLength;

function writeAsciiString (buffer, from, str) {
  for (var i = 0; i < str.length; i++) {
    var c = str.charCodeAt(i);
    if (c >= 128) {
      throw new Error('Non-ASCII character in string');
    }
    buffer[from + i] = c;
  }
}

function readAsciiString (buffer, from, to) {
  var str = '';
  for (var i = from; i < to; i++) {
    var c = buffer[i];
    if (c === 0) return str;
    str += String.fromCharCode(c);
  }
  return str;
}

function writeLEUint32 (buffer, from, value) {
  for (var i = 0; i < 4; i++) {
    buffer[from + i] = value % 256;
    value = (value - value % 256) / 256;
  }
}

function readLEUint32 (buffer, from) {
  var value = 0;
  var multiplier = 1;
  for (var i = 0; i < 4; i++) {
    value += buffer[from + i] * multiplier;
    multiplier *= 256;
  }
  return value;
}

function writeBuffer (buffer, from, fragment) {
  for (var i = 0; i < fragment.length; i++) {
    buffer[from + i] = fragment[i];
  }
}

exports.serialize = function (box) {
  var len = constLength + box.ciphertext.length;
  var buffer = new Uint8Array(len);

  writeAsciiString(buffer, 0, box.algorithm.id);
  writeLEUint32(buffer, 8, box.algorithm.opslimit);
  writeLEUint32(buffer, 12, box.algorithm.memlimit);
  writeBuffer(buffer, 16, box.salt);
  writeBuffer(buffer, 16 + box.salt.length, box.ciphertext);
  return buffer;
};

exports.deserialize = function (buffer) {
  if (buffer.length < overheadLength) {
    throw new Error('Insufficient buffer length: ' + buffer.length +
      ', minimum ' + overheadLength + ' expected');
  }

  return {
    algorithm: {
      id: readAsciiString(buffer, 0, 8),
      opslimit: readLEUint32(buffer, 8),
      memlimit: readLEUint32(buffer, 12)
    },
    salt: buffer.subarray(16, 16 + constants.scrypt.saltLength),
    ciphertext: buffer.subarray(16 + constants.scrypt.saltLength)
  };
};
