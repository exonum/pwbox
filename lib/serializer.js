'use strict';

const constants = require('./crypto-constants');

const constLength = 8 + // algorithm id
  4 + // memlimit
  4 + // opslimit
  constants.scrypt.saltLength; // salt

const overheadLength = constLength + constants.secretbox.overheadLength;

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
  return c;
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

module.exports = {

  overheadLength: overheadLength,

  serialize: function (box) {
    var len = constLength + box.ciphertext.length;
    var buffer = new Uint8Array(len);

    writeAsciiString(buffer, 0, box.algorithm.id);
    writeLEUint32(buffer, 8, box.algorithm.opslimit);
    writeLEUint32(buffer, 12, box.algorithm.memlimit);
    writeBuffer(buffer, 16, box.salt);
    writeBuffer(buffer, 16 + box.salt.length, box.ciphertext);
    return buffer;
  },

  deserialize: function (buffer) {
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
  }
};
