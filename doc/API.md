# pwbox API

Password-based encryption routines. See [main readme](../README.md) for a quick
tutorial and [a separate specification](./cryptography.md) for more details
on crypto.

## Table of Contents

  * [Constants](#constants)
  * [`pwbox`](#pwbox)
  * [`pwbox.open`](#pwboxopen)
  * [`pwbox.orFalse` and `pwbox.open.orFalse`](#orfalse-variants)

## Constants

```none
pwbox.defaultOpslimit = 524288
```
The default operations limit for scrypt. The same as the interactive opslimit
for scrypt in NaCl.

```none
pwbox.defaultMemlimit = 16777216
```
The default memory limit for scrypt. The same as the interactive memlimit
for scrypt in NaCl.

```none
pwbox.saltLength = 32
```
Length of salt used in pwbox. The same as that for scrypt.

```none
pwbox.overheadLength = 64
```
The ovehead length of serialized pwbox compared to the unencrypted message.

## pwbox

```none
function pwbox(message, password, [options={}], [callback])
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

```none
function pwbox.open(box, password, [callback])
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

## `orFalse` variants

```none
function pwbox.orFalse(message, password, [options], callback)
function pwbox.open.orFalse(box, password, callback)
```

Variants of [`pwbox`](#pwbox) and [`pwbox.open`](#pwboxopen), respectively,
that have a single-argument callback. Compared to the base versions of corresponding
functions, `orFalse` variants differ in the following ways:

- The callback is a mandatory argument of the function, rather than an optional
  one. The function will throw a `TypeError` if a callback is not supplied.
- A callback is called with a single argument, corresponding to the result of
  computations. If the original version of the function fails with an async error,
  the `orFalse` variant calls the callback with `false`. Note that `false` is
  not a valid result in either `pwbox` or `pwbox.open`, so using `false`
  as a failure marker does not create ambiguities.

In all other ways, `orFalse` variants behave exactly as their base counterparts.
