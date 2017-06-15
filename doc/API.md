# pwbox API

Password-based encryption routines. See [main readme](../README.md) for a quick
tutorial and [a separate specification](./cryptography.md) for more details
on crypto.

## Table of Contents

  * [Constants](#constants)
  * [pwbox](#pwbox)
  * [pwbox.open](#pwboxopen)

## Constants

```javascript
pwbox.defaultOpslimit = 524288
```
The default operations limit for scrypt. The same as the interactive opslimit
for scrypt in NaCl.

```javascript
pwbox.defaultMemlimit = 16777216
```
The default memory limit for scrypt. The same as the interactive memlimit
for scrypt in NaCl.

```javascript
pwbox.saltLength = 32
```
Length of salt used in pwbox. The same as that for scrypt.

```javascript
pwbox.overheadLength = 64
```
The ovehead length of serialized pwbox compared to the unencrypted message.

## pwbox

```javascript
function pwbox (message, password, [options={}], [callback])
```

Performs password-based encryption using scrypt for key derivation and
NaCl's secretbox for symmetric encryption.

### Arguments

  * **message:** Uint8Array  
    Message to encrypt
  * **password:** Uint8Array|String  
    Password to use for encryption
  * **options:** Object  
    Encryption options:
      * **salt:** [Uint8Array]  
        Salt to use in derivation. You should *never* specify the salt manually,
        except for testing purposes. If not specified explicitly, the salt is generated
        randomly
      * **opslimit:** [Number]  
        opslimit for scrypt with the same meaning as in NaCl/libsodium.
        The default value is `pwbox.defaultOpslimit`
      * **memlimit:** [Number]  
        memlimit for scrypt with the same meaning as in NaCl/libsodium.
        The default value is `pwbox.defaultMemlimit`

  * **callback:** [Function]  
    Function that will be called when encryption is complete. The callback has
    a Node standard form `cb(err, box)`, where `err` is a possible execution error,
    and `box` is the encrypted box

### Return value

If `pwbox` is called with a callback, the function returns nothing; it always returns
before the callback is called. If `pwbox` is called without a callback,
it returns a `Promise` with the encrypted box.

## pwbox.open

```javascript
function pwbox.open (box, password, [callback])
```

Decrypts a box that was previously encrypted with `pwbox`.

### Arguments

  * **box:** Uint8Array  
    Encrypted box
  * **password:** Uint8Array|String  
    Password that was used during password encryption  
  * **callback:** [Function]  
    Function that will be called when decryption is complete. The callback has
    a Node standard form `cb(err, message)`, where `err` is a possible execution error,
    and `message` is the decrypted message

### Return value

If `pwbox.open` is called with a callback, the function returns nothing; it always returns
before the callback is called. If `pwbox.open` is called without a callback,
it returns a `Promise` with the decrypted message.
