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
The default operations limit. The same as the *interactive* opslimit
for scrypt in libsodium.

```javascript
pwbox.defaultMemlimit = 16777216
```
The default memory limit. The same as the *interactive* memlimit
for scrypt in libsodium.

```javascript
pwbox.minOpslimit = 32768
```
The minimum operations limit. The same as in libsodium.

```javascript
pwbox.minMemlimit = 16777216
```
The minimum memory limit. The same as in libsodium.

```javascript
pwbox.maxOpslimit = 33554432
```
The maximum operations limit. The same as the *sensitive* opslimit
for scrypt in libsodium.

```javascript
pwbox.maxMemlimit = 1073741824
```
The maximum memory limit. The same as the *sensitive* memlimit
for scrypt in libsodium.


```javascript
pwbox.saltLength = 32
```
Length of salt used in pwbox. The same as that for scrypt.

```javascript
pwbox.overheadLength = 64
```
The ovehead length of serialized pwbox compared to the unencrypted message.

## Defined Types

### BoxObject

JS object returned when the `'object'` encoding is specified for [`pwbox`](#pwbox).
Box objects can also be consumed by [`pwbox.open`](#pwboxopen).

  * **algorithm:** Object  
    Describes the key derivation algorithm used during box creation.
    
    * **algorithm.id:** `'scrypt'`  
      Algorithm identifier (always `'scrypt'`).
    * **algorithm.opslimit:** Number  
      Operations limit used with the key derivation algorithm to create the box.
    * **algorithm.memlimit:** Number  
      Memory limit used with the key derivation algorithm to create the box.

  * **salt:** Uint8Array  
    Cryptographic salt used for key derivation. Salt length is equal to `pwbox.saltLength`.
  * **ciphertext:** Uint8Array
    Encrypted message as returned by sodium/NaCl's `secretbox`.

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
        Operations limit for scrypt with the same meaning as in NaCl/libsodium.
        The default value is `pwbox.defaultOpslimit`.
        Must be in the interval [`pwbox.minOpslimit`, `pwbox.maxOpslimit`].
      * **memlimit:** [Number]  
        RAM usage limit for scrypt with the same meaning as in NaCl/libsodium.
        The default value is `pwbox.defaultMemlimit`.
        Must be in the interval [`pwbox.minMemlimit`, `pwbox.maxMemlimit`].
      * **encoding:** [`'object'`|`'binary'`]  
        Format for the returned box. `'binary'` (default) means that the box
        is returned as a `Uint8Array`. `'object'` means that the box returned
        as an [object](#boxobject).

  * **callback:** [Function]  
    Function that will be called when encryption is complete. The callback has
    a Node standard form `cb(err, box)`, where `err` is a possible execution error,
    and `box` is the encrypted box

> **Tip.** See [the cryptographic spec](cryptography.md#parameter-validation) for
> restrictions on `opslimit` and `memlimit` parameters and recommendations on
> their reasonable values.

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

  * **box:** Uint8Array|BoxObject  
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
