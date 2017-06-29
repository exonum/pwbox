# Password-Based Encryption for Node and Browsers

[![Build status][travis-image]][travis-url]
[![Code style][code-style-image]][code-style-url]
[![License][license-image]][license-url]

[travis-image]: https://img.shields.io/travis/exonum/pwbox.svg?style=flat-square
[travis-url]: https://travis-ci.com/exonum/pwbox
[code-style-image]: https://img.shields.io/badge/code%20style-semistandard-brightgreen.svg?style=flat-square
[code-style-url]: https://github.com/Flet/semistandard
[license-image]: https://img.shields.io/github/license/exonum/pwbox.svg?style=flat-square
[license-url]: https://opensource.org/licenses/Apache-2.0

**pwbox** is a JS library for password-based encryption. It is similar to
NaCl/libsodium's built-in `secretbox`, only it implements
encryption based on passwords rather on secret keys.

Behind the scenes, pwbox uses crypto-primitves from NaCl/libsodium:
- `pwhash_scryptsalsa208sha256` for key derivation
- `secretbox` routines for key-based symmetric encryption

**Security Notice.** Use this software at your own risk. You should think carefully
before using this (or any other) software to ensure browser-based client-side
security; browser environments are somewhat unsecure.

## Getting Started

Import pwbox to your project:

```javascript
var pwbox = require('pwbox');
```

...and use it similarly to `secretbox` in [TweetNaCl.js](http://tweetnacl.js.org/):

```javascript
var password = 'pleaseletmein';
var message = new Uint8Array([ 65, 66, 67 ]);

pwbox(message, password).then(box => {
  console.log(box);
  return pwbox.open(box, password);
}).then(opened => {
  console.log(opened);
});
```

`pwbox` (encryption routine) and `pwbox.open` (decryption routine) are asynchronous;
they support either callbacks or promises.
See [the API docs](doc/API.md) for more details.

The same example as above, with callbacks.

```javascript
var password = 'pleaseletmein';
var message = new Uint8Array([ 65, 66, 67 ]);

pwbox(message, password, function (err, box) {
  console.log(box);
  pwbox.open(box, password, function (err, opened) {
    console.log(opened);
  });
});
```

You may also invoke `pwbox` and `pwbox.open` with a single-argument callback.
Just use `.orFalse` after the call:

```javascript
var box = // ...
pwbox.open.orFalse(box, password, function (opened) {
  if (!opened) {
    // do error handling
    return;
  }
  // use opened
});
```

In this case, the callback will be called with `false` if an error occurs during the call.

### Encoding Messages

**pwbox** requires for a message to be a `Uint8Array` instance. This means you can
encrypt binary data (e.g., private keys) without any conversion. If you want
to encrypt *string* data, you need to convert it to `Uint8Array`. This can be
accomplished in several ways.

#### Using `Buffer`

Node has [`Buffer.from(str, encoding)`][node-bufferfrom] method
and its older version, [`new Buffer(str, encoding)`][node-newbuffer] to
convert from strings to byte buffers.
For the complementary operation, you may use [`buffer.toString(encoding)`][node-buffertostring].
These methods are also available
via [the `buffer` package][npm-buffer] in browser environments. As `Buffer`s
inherit from `Uint8Array`, you may freely pass them as messages.

#### Using `enodeURIComponent`

Browsers [can also use][so-str-to-buffer]
built-in `enodeURIComponent` and `decodeURIComponent` methods for the conversion:

```javascript
function toUint8Array (str) {
  str = unescape(encodeURIComponent(str));
  var buffer = new Uint8Array(str.length);
  for (var i = 0; i < buffer.length; i++) {
    buffer[i] = str[i].charCodeAt(0);
  }
  return buffer;
}

function fromUint8Array (buffer) {
  var encodedString = String.fromCharCode.apply(null, buffer);
  var decodedString = decodeURIComponent(escape(encodedString));
  return decodedString;
}
```

> **Tip.** Although it's not strictly necessary, you may convert the password
> into a `Uint8Array` in the same way as the message.

## Options

**pwbox** supports tuning the scrypt parameters using `opslimit` and `memlimit` from
libsodium. These parameters determine the amount of computations and
the RAM usage, respectively, for `pwbox` and `pwbox.open`.

```javascript
pwbox(message, password, {
  opslimit: 1 << 20, // 1M
  memlimit: 1 << 25  // 32M
}).then(box => console.log(box));
```

The default values for `opslimit` and `memlimit` are also taken from libsodium
(`524288` and `16777216`, respectively). With the default parameters, `pwbox`
uses 16 MB of RAM and completes
with a comfortable 100ms delay in Node, several hundred ms in browsers
on desktops/laptops, and under a second on smartphones.
You may use increased parameter values for better security;
see the [crypto spec](doc/cryptography.md#parameter-validation) for more details.

### Backends

**pwbox** may use one of the following cryptographic backends:

- [libsodium-wrappers-sumo][libsodium]
- [tweetnacl][tweetnacl] + [scrypt-async][scrypt-async] (default)

To use a non-default backend, call `pwbox.withCrypto` with `'tweetnacl'`
or `'libsodium'`; it will return the
object with the same interface as `pwbox` itself.

```javascript
var sodiumPwbox = require('pwbox').withCrypto('libsodium');
sodiumPwbox(message, password).then(/* ... */);
```

You may even supply your own backend by passing an object to `withCrypto`!
[See documentation](doc/API.md#withcrypto) for more details.

## Lite Version and Use in Browsers

`require('pwbox/lite')` loads a simplified version of **pwbox**, which
uses a fixed backend (tweetnacl + scrypt-async) and has no `withCrypto` function.
This is the preferred way to use **pwbox** in browsers, as the full version
of the librabry is quite bulky. You may use `'pwbox/lite'` together with
your favorite browserifier (say, `browserify` or `webpack`), or
import a readymade browserified and minified lite package directly
from the **dist** directory of the package.

[libsodium]: https://www.npmjs.com/package/libsodium-wrappers-sumo
[tweetnacl]: https://www.npmjs.com/package/tweetnacl
[scrypt-async]: https://www.npmjs.com/package/scrypt-async

## License

Copyright (c) 2017, Bitfury Group Limited

**pwbox** is licensed under [Apache 2.0 license](LICENSE).

[node-bufferfrom]: https://nodejs.org/dist/latest-v6.x/docs/api/buffer.html#buffer_class_method_buffer_from_string_encoding
[node-newbuffer]: https://nodejs.org/dist/latest-v6.x/docs/api/buffer.html#buffer_new_buffer_string_encoding
[node-buffertostring]: https://nodejs.org/dist/latest-v6.x/docs/api/buffer.html#buffer_buf_tostring_encoding_start_end
[npm-buffer]: https://www.npmjs.com/package/buffer
[so-str-to-buffer]: https://stackoverflow.com/questions/17191945/conversion-between-utf-8-arraybuffer-and-string
