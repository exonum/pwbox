# Passphrase-based Encryption for Node and Browsers

pwbox is just like NaCl/libsodium's built-in `secretbox`, only it implements
encryption based on passwords rather on secret keys.

Behind the scenes, pwbox uses crypto-primitves from NaCl/libsodium:
  * `pwhash_scryptsalsa208sha256` for key derivation
  * `secretbox` routines for key-based symmetric encryption
  
**Security Notice.** Use this software at your own risk. You should think twice
before using this (or any other) software to ensure browser-based client-side
security; browser environments are notoriously unsecure.

## Getting Started

Import pwbox to your project:
```javascript
var pwbox = require('pwbox');
```

...and use it similarly to `secretbox` in [TweetNaCl](http://tweetnacl.js.org/):
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

`pwbox` calls are asynchronous; they support either callbacks or promises.
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

You may also invoke `pwbox` and `pwbox.open` with a single-argument callback 
if you are not used to Node-style callbacks. Just use `.orFalse` after the call:
```javascript
var box = // ...
pwbox.open.orFalse(box, password, function (opened) {
  if (!opened) {
    // do error handling
  }
  // use opened
});
```

In this case, the callback will be called with `false` if an error occurs during the call.

### Options

pwbox supports tuning the scrypt parameters using `opslimit` and `memlimit` from
libsodium.

```javascript
pwbox(message, password, {
  opslimit: 1 << 20, // 1M
  memlimit: 1 << 25  // 32M
}).then(box => console.log(box));
```

The default values for `opslimit` and `memlimit` are also taken from libsodium
(`524288` and `16777216`, respectively). With default parameters, the function completes 
with a comfortable 100ms delay in Node, and slightly more in browsers.

### Backends

pwbox may use one of the following backends:
  * [libsodium-wrappers-sumo][libsodium]
  * [tweetnacl][tweetnacl] + [scrypt-async][scrypt-async] (default)
  
To use a non-default backend, call `pwbox.withCrypto`; it will return the
object with the same interface as `pwbox` itself.

```javascript
var sodiumPwbox = require('pwbox').withCrypto('libsodium');
sodiumPwbox(message, password).then(/* ... */);
```

You may even supply your own backend by passing an object to `withCrypto`!
See documentation for more details.

[libsodium]: https://www.npmjs.com/package/libsodium-wrappers-sumo
[tweetnacl]: https://www.npmjs.com/package/tweetnacl
[scrypt-async]: https://www.npmjs.com/package/scrypt-async

## License

Copyright (c) 2017, Bitfury Group Limited  

pwbox is licensed under [Apache 2.0 license](LICENSE). 
