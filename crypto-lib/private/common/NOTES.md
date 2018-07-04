# Organization

## `error.rkt`

The operations in this library report errors with the "who" field set
to the operation performed by the client rather than the name of the
internal helper method or procedure where the error occurred. The
`error.rkt` file infrastructure to make that convenient (the
operation's name is stored as a continuation-mark, which works fine
for first-order, single-threaded code). The file also contains a few
helpers for generating consistent error messages.

## `interfaces.rkt`

Other than algorithm specifiers (eg, `digest-spec?`), which are
represented by S-expressions, most types provided by this library are
represented by classes, although clients are expected to use the
procedures defined in `crypto/main` rather than calling methods on the
objects directly. The `interfaces.rkt` defines the interfaces between
`crypto/main` and implementations and within implementations.

There are three main interfaces:

- `factory<%>` -- each provider (eg, libcrypto or nettle) defines a
  singleton factory object implementing this interface that maps
  algorithm specs to impls (`impl<%>` instances)

- `impl<%>` -- represents an algorithm implementation; there is a
  sub-interface for each kind of algorithm (eg `digest-impl<%>`)

- `ctx<%>` -- represents incremental state in the execution of some
  algorithm; for example, a message digest can be computed by creating
  a `digest-ctx<%>` instance (tied to a particular `digest-impl<%>`),
  feeding it input incrementally (using the `update` method), and
  extracting the result (using the `final` method)

## `catalog.rkt`

The catalog contains is a database that maps algorithm specs (eg,
`digest-spec?`, `cipher-spec?` and its components, etc) to information
about the algorithm (eg, block size, key length, etc).

## `common.rkt`, `digest.rkt`, `cipher.rkt`, `kdf.rkt`

This file contains abstract base classes with default behavior and
helpers to make implementations simpler. For example, the
`cipher-ctx%` class in `cipher.rkt` handles AEAD authentication with
both attached and detached authentication tags, block buffering (for
implementations that require block-aligned input), padding, etc.

### Configurations

Some KDF and PK operations require parameters that differ from
algorithm to algorithm. For example, RSA key generation needs `nbits`
(the size of the modulus) whereas EC key generation needs the name of
the elliptic curve. These are represented by alists called
*configurations* (or *config*s), and `common.rkt` has code for
validating configs and extracting keys.

## Public-key cryptography support

`pk-asn1.rkt` -- ASN.1 definitions for common types like
AlgorithmIdentifier, SubjectPublicKeyInfo, PrivateKeyInfo, etc; and
lots of OID definitions.

`pk-common.rkt` -- Base classes, key format codecs (using types from
`pk-asn1.rkt`). Lots of effort is dedicated to letting implementations
declare what operations, options (eg padding), etc they support. (This
is particularly useful for scripting the tests.)

----------------------------------------

# Misc Implementation Notes

## Random numbers/bytestrings

Some operations generate random numbers internally, such as RSA key
generation. Those use the implementation's CSPRNG support, whatever
form that may take.

When random numbers (or bytestrings) are required as arguments, they
are generated using Racket's `crypto-random-bytes` procedure.
