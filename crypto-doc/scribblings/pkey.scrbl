#lang scribble/doc
@(require scribble/manual
          scribble/basic
          racket/list
          crypto/private/common/catalog
          (for-label racket/base
                     racket/contract
                     crypto crypto/pkcs8))

@title[#:tag "pk"]{Public-Key Cryptography}

Public-key (PK) cryptography covers operations such as
@seclink["pk-sign"]{signing}, @seclink["pk-encrypt"]{encryption}, and
@seclink["pk-keyagree"]{key agreement} between parties that do not
start with any shared secrets. Instead of shared secrets, each party
possesses a keypair consisting of a secret private key and a
widely-published public key. Not all PK cryptosystems support all PK
operations (for example, DSA does not support encryption or secret
derivation), and some PK implementations may support a subset of a PK
cryptosystem's potential operations.


@defproc[(pk-spec? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is a PK cryptosystem specifier,
@racket[#f] otherwise.

A PK cryptosystem specifies the information represented by the public and
private keys and the algorithms that operate on that information. The
following PK systems are supported:

@itemlist[

@item{@racket['rsa] --- @as-index{RSA} keys with RSAES-* encryption
and RSASSA-* signing @cite{PKCS1}.}

@item{@racket['dsa] --- @as-index{DSA} keys with DSA signing.}

@item{@racket['dh] --- @as-index{Diffie-Hellman} key agreement using
modular integer arithmetic @cite{RFC2631}.}

@item{@racket['ec] --- Elliptic curve keys with @as-index{ECDSA}
signing and @as-index{ECDH} key agreement @cite{SEC1}. Only named
curves are supported, and different implementations support different
curves; use @racket[factory-print-info] to see supported curves.}

@item{@racket['eddsa] --- Edwards curve keys with @as-index{EdDSA} signing,
specifically @as-index{Ed25519} and @as-index{Ed448}.}

@item{@racket['ecx] --- Montgomery curve keys with ECDH key agreement,
specifically @as-index{X25519} and @as-index{X448}.}

]

@history[#:changed "1.1" @elem{Added @racket['eddsa] and @racket['ecx].}]
}

@defproc[(pk-impl? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is a PK cryptosystem implementation,
@racket[#f] otherwise.
}

@defproc[(get-pk [pki pk-spec?]
                 [factories (or/c crypto-factory? (listof crypto-factory?))])
         (or/c pk-impl? #f)]{

Returns an implementation of PK algorithm @racket[pki] from the given
@racket[factories]. If no factory in @racket[factories] implements
@racket[pki], returns @racket[#f].
}

@deftogether[[
@defproc[(pk-can-sign? [pk (or/c pk-impl? pk-key?)]) boolean?]
@defproc[(pk-can-encrypt? [pk (or/c pk-impl? pk-key?)]) boolean?]
@defproc[(pk-can-key-agree? [pk (or/c pk-impl? pk-key?)]) boolean?]
]]{

Indicates whether the cryptosystem implementation @racket[pk] (or the
implementation corresponding to @racket[pk], if @racket[pk] is a key)
supports signing, encryption, and key agreement, respectively.

Note that the functions only report the capabilities of the
cryptosystem implementation, regardless of the limitations of
@racket[pk] if @racket[pk] is a key. For example,
@racket[(pk-can-sign? pk)] would return true when @racket[pk] is an
RSA public-only key, even though signing requires a private key.
}

@defproc[(pk-has-parameters? [pk (or/c pk-impl? pk-key?)]) boolean?]{

Returns @racket[#f] if the PK cryptosystem represented by @racket[pk]
uses key parameters, @racket[#f] otherwise. See @secref["pk-keys"] for
more information.
}


@section[#:tag "pk-keys"]{PK Keys and Parameters}

A PK keypair consists of public key component and private key
components. A public key is a key that contains the public key
components. In this library, a private key contains both private and
public components, so it can also be used wherever a public key is
required. That is, every private key is also a public key. This
library uses the term ``public-only key'' to refer to a public key
that is not a private key.

In some PK cryptosystems, the public components are further divided
into key-specific values and ``key parameters.'' Key parameters are
public quantities that are expensive to compute; they can be generated
once and many keypairs can use the same parameter values. For example,
a DSA key requires a large prime with certain relatively rare
mathematical properties, and so finding such a prime is relatively
expensive, but once a suitable prime is found, generating private keys
is relatively fast, and since the prime is public, many keypairs can
use the same prime. Elliptic curve (EC) cryptography is another
example: the key parameter is the curve equation, and the public and
private key components are points on the curve. In contrast, RSA does
not have key parameters; simple quantities like the size of an RSA
modulus are not key parameters.

@defproc[(pk-key? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is a public key or a private key,
@racket[#f] otherwise. Since all PK keys contain the public key
components, @racket[pk-key?] is a predicate for public keys.
}

@defproc[(private-key? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is a private key.
}

@defproc[(public-only-key? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is a public key but not a private
key, @racket[#f] otherwise. Equivalent to @racket[(and (pk-key? v)
(not (private-key? v)))].
}

@defproc[(pk-parameters? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is a value representing PK key
parameters for some cryptosystem, @racket[#f] otherwise.
}

@defproc[(pk-key->parameters [pk pk-key?]) (or/c pk-parameters? #f)]{

Returns a value representing the key parameters of @racket[pk], or
@racket[#f] if @racket[pk]'s cryptosystem does not use key parameters.
}

@defproc[(pk-security-strength [pk (or/c pk-key? pk-parameters?)])
         (or/c #f security-strength/c)]{

Returns the @tech{security strength} rating for the given PK key or
parameters. If @racket[pk] does not support strength calculation,
@racket[#f] is returned.

@history[#:added "1.8"]}

@defproc[(public-key=? [pk1 pk-key?] [pk2 pk-key?] ...) boolean?]{

Returns @racket[#t] if the public key components of @racket[pk1] and
@racket[pk2] are equal, @racket[#f] otherwise. One use of this
function is to check whether a private key matches some public-only
key.
}

@defproc[(pk-key->public-only-key [pk pk-key?]) public-only-key?]{

Returns a public-only key @racket[_pub-pk] such that
@racket[(public-key=? pk _pub-pk)]. If @racket[pk] is already a
public-only key, the function may simply return @racket[pk].
}


@defproc[(generate-pk-parameters [pki (or/c pk-spec? pk-impl?)]
                                 [paramgen-config (listof (list/c symbol? any/c)) 
                                                  '()])
         pk-parameters?]{

Generate PK parameter values for the cryptosystem of @racket[pki]
using the given configuration options. The default values of optional
configuration arguments are implementation-dependent.

The acceptable configuration values depend on @racket[pki].
@itemlist[

@item{The following configuration values are recognized for DSA
(@racket['dsa]):
@itemlist[

@item{@racket[(list 'nbits _nbits)] --- Optional. Generate a prime
modulus of size @racket[_nbits]. Examples include @racket[1024] and
@racket[2048].}

]}

@item{The following configuration values are recognized for DH
(@racket['dh]): 
@itemlist[

@item{@racket[(list 'nbits _nbits)] --- Optional. Generate a prime
modulus of size @racket[_nbits]. Examples include @racket[1024] and
@racket[2048].}

@item{@racket[(list 'generator _generator)] --- Optional. Use the
given @racket[_generator]; must be either @racket[2] or @racket[5].}

]}

@item{The following configuration values are recognized for EC
(@racket['ec]):
@itemlist[

@item{@racket[(list 'curve _curve-name)] --- Required. Use the standard curve
named @racket[_curve-name]. Examples include @racket["NIST P-256"] and
@racket["secp192r1"]. Use @racket[factory-print-info] to show available curves.}

]}

@item{The following configuration values are recognized for EdDSA
(@racket['eddsa]):
@itemlist[

@item{@racket[(list 'curve _curve-sym)] --- Required. Generate a key
for the given curve. The @racket[_curve-sym] must be @racket['ed25519]
or @racket['ed448].}

]}

@item{The following configuration values are recognized for @racket['ecx]:
@itemlist[

@item{@racket[(list 'curve _curve-sym)] --- Required. Generate a key
for the given curve. The @racket[_curve-sym] must be @racket['x25519]
or @racket['x448].}

]}

]

@history[#:changed "1.1" @elem{Added @racket['eddsa] and @racket['ecx] options.}]
}


@defproc[(generate-private-key [pki (or/c pk-spec? pk-impl? pk-parameters?)]
                               [keygen-config (listof (list/c symbol? any/c)) '()])
         private-key?]{

Generate a private key from the given PK implementation or PK
parameters. The default values of optional configuration arguments are
implementation dependent.

The accepted configuration arguments depend on @racket[pki]:
@itemlist[

@item{If @racket[pki] is a PK parameters object (@racket[pk-parameters?]),
then @racket[keygen-config] must be empty.}

@item{The following configuration values are recognized for RSA
(@racket['rsa]):
@itemlist[

@item{@racket[(list 'nbits _nbits)] --- Optional. Generate a modulus
of size @racket[_nbits]. Examples include @racket[1024] and
@racket[2048].}

]}

@item{If @racket[pki] is a PK specifier (@racket[pk-spec?]) or PK
implementation (@racket[pk-impl?]), then the same configuration
arguments are supported as for @racket[generate-parameters]. This is
equivalent to @racket[(generate-private-key (generate-pk-parameters
pki keygen-config) '())].

}]

}


@section[#:tag "pk-sign"]{PK Signatures}

In PK signing, the sender uses their own private key to sign a
message; any other party can verify the sender's signature using the
sender's public key.

In RSA, DSA, and ECDSA, only short messages can be signed directly (limits are
generally proportional to the size of the keys), so a typical process is to
compute a digest of the message and sign the digest. The message and digest
signature are sent together, possibly with additional data.

In EdDSA, messages are signed directly. (The signing process computes a message
digest internally.)

@defproc[(pk-sign [pk private-key?]
                  [msg bytes?]
                  [#:pad padding (or/c #f 'pkcs1-v1.5 'pss 'pss*) #f]
                  [#:digest dspec (or/c digest-spec? 'none #f) #f])
         bytes?]{

Returns the signature using the private key @racket[pk] of the message
@racket[msg].

If @racket[pk] is an RSA private key, then @racket[padding] must be
one of the following:
@itemlist[
@item{@racket['pkcs1-v1.5] or @racket[#f] --- use PKCS#1-v1.5 padding}
@item{@racket['pss] --- use PSS padding with a salt length equal to
@racket[(digest-size di)]}
@item{@racket['pss*] --- sign using PSS padding with a salt length
equal to @racket[(digest-size di)], but infer the salt length when
verifying}
]
For all other cryptosystems, @racket[padding] must be @racket[#f].

If @racket[pk] is an RSA private key, then @racket[dspec] must be the name
of a digest algorithm, and @racket[msg] must be a digest computed with
@racket[dspec] (in particular, it must have the correct size for
@racket[dspec]). The resulting signature depends on the identity of the
digest algorithm. Different RSA implementations may support different digest
algorithms.

If @racket[pk] is a DSA or EC private key, the signature does not depend on
the digest algorithm; the @racket[dspec] should be omitted. (For backwards
compatibility, the @racket[dspec] argument is accepted, but it has no effect
other than checking the length of @racket[msg].)

If @racket[pk] is a EdDSA private key, then @racket[dspec] must be
@racket[#f] or @racket['none] (both values mean the same thing). The message
may be of any length, and the EdDSA signature is computed. Future versions
of this library may accept other values of @racket[dspec] and compute
HashEdDSA signatures (eg, Ed25519ph) in reponse.

@history[#:added "1.1"]
}

@defproc[(pk-verify [pk pk-key?]
                    [msg bytes?]
                    [sig bytes?]
                    [#:digest dspec (or/c digest-spec? #f 'none) #f]
                    [#:pad padding (or/c #f 'pkcs1-v1.5 'pss) #f])
         boolean?]{

Returns @racket[#t] if @racket[pk] verifies that @racket[sig] is a valid
signature of the message @racket[msg], or @racket[#f] if the signature is
invalid.

The @racket[dspec] and @racket[padding] arguments have the same meanings as
for @racket[pk-sign].

@history[#:added "1.1"]
}

@deftogether[[
@defproc[(digest/sign [pk private-key?]
                      [di (or/c digest-spec? digest-impl?)]
                      [input input/c]
                      [#:pad padding (or/c #f 'pkcs1-v1.5 'pss) #f])
         bytes?]
@defproc[(digest/verify [pk pk-key?]
                        [di (or/c digest-spec? digest-impl?)]
                        [input input/c]
                        [sig bytes?]
                        [#:pad padding (or/c #f 'pkcs1-v1.5 'pss) #f])
         boolean?]
]]{

Computes or verifies signature of the @racket[di] message digest of
@racket[input]; equivalent to calling @racket[digest] then
@racket[pk-sign-digest] or @racket[pk-verify-digest], respectively.

Do not use these functions with EdDSA keys; use @racket[pk-sign] and
@racket[pk-verify] directly on the messages. (This library currently does
not support pre-hashing EdDSA variants, eg Ed25519ph.)
}

@deftogether[[
@defproc[(pk-sign-digest [pk private-key?]
                         [di (or/c digest-spec? digest-impl?)]
                         [dgst bytes?]
                         [#:pad padding (or/c #f 'pkcs1-v1.5 'pss 'pss*) #f])
         bytes?]
@defproc[(pk-verify-digest [pk pk-key?]
                           [di (or/c digest-spec? digest-impl?)] 
                           [dgst bytes?]
                           [sig bytes?]
                           [#:pad padding (or/c #f 'pkcs1-v1.5 'pss) #f])
         boolean?]
]]{

Equivalent to @racket[(pk-sign pk dgst #:digest di #:pad padding)] and
@racket[(pk-verify pk dgst sig #:digest di #:pad padding)], respectively.
}


@section[#:tag "pk-encrypt"]{PK Encryption}

In PK encryption, the sender uses the public key of the intended
receiver to encrypt a message; the receiver decrypts the message with
the receiver's own private key. Only short messages can be directly
encrypted using PK cryptosystems (limits are generally proportional to
the size of the PK keys), so a typical approach is to encrypt the
message using a symmetric cipher with a randomly-generated key
(sometimes called the bulk encryption key) and encrypt that key using
PK cryptography. The symmetric-key-encrypted message and PK-encrypted
symmetric key are sent together, perhaps with additional data such as
a MAC. PK encryption is supported by the RSA cryptosystem.

@deftogether[[
@defproc[(pk-encrypt [pk pk-key?]
                     [msg bytes?]
                     [#:pad padding (or/c #f 'pkcs1-v1.5 'oaep) #f])
         bytes?]
@defproc[(pk-decrypt [pk private-key?]
                     [msg bytes?]
                     [#:pad padding (or/c #f 'pkcs1-v1.5 'oaep) #f])
         bytes?]
]]{

Encrypt or decrypt, respectively, the message @racket[msg] using PK
key @racket[pk].

If @racket[pk] is an RSA key, then @racket[padding] choses between
PKCS#1-v1.5 padding and OAEP padding @cite{PKCS1}. If @racket[padding]
is @racket[#f], then an implementation-dependent mode is chosen. For
all other cryptosystems, @racket[padding] must be @racket[#f].

If @racket[msg] is too large to encrypt using @racket[pk], then an
exception is raised.

@;{FIXME: what if decryption fails???!!!}
}

@;{Why no envelope functions? Because difficult to include
authenticity, and attractive nuisance if it doesn't.}

@section[#:tag "pk-keyagree"]{PK Key Agreement}

In PK @as-index{key agreement} (sometimes called @as-index{key
exchange} or @as-index{Diffie-Hellman}) two parties derive a shared
secret by exchanging public keys. Each party can compute the secret
from their own private key and the other's public key, but it is
believed infeasible for an observer to compute the secret from the two
public keys alone. PK secret derivation is supported by the
@racket['dh], @racket['ec], and @racket['ecx] cryptosystems.

@defproc[(pk-derive-secret [pk private-key?]
                           [peer-pk (or/c pk-key? bytes?)])
         bytes?]{

Returns the shared secret derived from the private key @racket[pk] and
the public key @racket[peer-pk]. If @racket[peer-pk] is a PK key, it
must be a key compatible with @racket[pk] (same algorithm and same
parameters); otherwise an exception is raised. If @racket[peer-pk] is
a bytestring, an exception is raised if it cannot be interpreted as
raw public key data.

Note that the derived secret is a deterministic function of the
private keys: if two parties perform secret derivation twice, they
will produce the same secret both times. In addition, the secret is
not uniformly distributed. For these reasons, the derived secret
should not be used directly as a key; instead, it should be used to
generate key material using a key-derivation function (see
@racket[kdf]).
}

@section[#:tag "pk-external"]{PK External Representations}

This section describes serialization of public and private keys in
various formats.

@defproc[(pk-key->datum [pk pk-key?] [fmt symbol?])
         printable/c]{

Returns a datum representing the key @racket[pk], where the encoding
is selected by @racket[fmt]. Unless noted below, the result is a
bytestring (@racket[bytes?]). The following @racket[fmt] options are
supported:

@itemlist[

@item{@racket['SubjectPublicKeyInfo] --- DER-encoded
SubjectPublicKeyInfo @cite["PKIX"] representation of the public part
of @racket[pk]. All key types are supported, and an identifier for the
key type is embedded in the encoding.

For compatibility with OpenSSL, DH keys are encoded using the PKCS #3
identifier and parameters @cite["PKCS3"] rather than those specified by
@cite["PKIX-AlgId"], and EdDSA keys are encoded using the algorithm
identifiers specified in the draft @cite["PKIX-EdC"].}

@item{@racket['PrivateKeyInfo] --- DER-encoded PrivateKeyInfo
@cite["PKCS8"] representation of @racket[pk], which must be a private
key. All key types are supported, and an identifier for the key type
is embedded in the encoding.

For DSA, DH, and EdDSA keys, the PrivateKeyInfo (version 1) format does not
store derived public-key fields. Some implementations (eg GCrypt) do not
expose the ability to recompute the public key, so they may not be able to
read such keys. See also @racket['OneAsymmetricKey].}

@item{@racket['OneAsymmetricKey] --- DER-encoded OneAsymmetricKey
@cite["AKP"] representation of @racket[pk], which must be a private
key. OneAsymmetricKey is essentially PrivateKeyInfo version 2; it adds an
optional field for the public key. Prefer OneAsymmetricKey for storing DSA,
DH, and EdDSA keys.}

@item{@racket['RSAPrivateKey] --- DER-encoded RSAPrivateKey
@cite["PKCS1"] representation of @racket[pk], which must be an RSA
private key.}

@;{@item{@racket['DSAPrivateKey] --- DER-encoded representation of
@racket[pk], which must be a DSA private key, in a non-standard format
used by OpenSSL.}}

@;{@item{@racket['ECPrivateKey] --- DER-encoded ECPrivateKey @cite{SEC1}
representation of @racket[pk], which must be an EC private key. Only
keys using named curves are supported.}}

@item{@racket['age/v1-private] --- String representing an X25519 private key
encoded in the @hyperlink["https://age-encryption.org/v1"]{age-encryption (v1)}
format. The string is Bech32-encoded and has 74 characters beginning with
@litchar{AGE-SECRET-KEY-1}.}

@item{@racket['age/v1-public] --- String representing an X25519 public key
encoded in the @hyperlink["https://age-encryption.org/v1"]{age-encryption (v1)}
format. The string is Bech32-encoded and has 62 characters beginning with
@litchar{age1}.}

@item{@racket['openssh-public] --- A string containing an OpenSSH-format public
key. The string starts with a tag such as @litchar{ssh-rsa} or
@litchar{ssh-ed25519}, then contains the key data encoded in Base64. Only RSA,
Ed25519, and Ed448 public keys are currently supported.}

@item{@racket['rkt-private] --- An S-expression of one of the following forms:

@itemlist[

@item{@racket[(list 'rsa 'private _n _e _d)]}
@item{@racket[(list 'dsa 'private _p _q _g _y _d)]}
@item{@racket[(list 'dh  'private _p _g _y _x)]}
@item{@racket[(list 'ec  'private _curve-oid _q-bytes _x)]}
@item{@racket[(list 'eddsa 'private _curve-sym _q-bytes _d-bytes)]}
@item{@racket[(list 'ecx 'private _curve-sym _q-bytes _d-bytes)]}

]}

@item{@racket['rkt-public] --- An S-expression of one of the following forms:

@itemlist[

@item{@racket[(list 'rsa 'public _n _e)]}
@item{@racket[(list 'dsa 'public _p _q _g _y)]}
@item{@racket[(list 'dh  'public _p _g _y)]}
@item{@racket[(list 'ec  'public _curve-oid _q-bytes)]}
@item{@racket[(list 'eddsa 'public _curve-sym _q-bytes)]}
@item{@racket[(list 'ecx 'public _curve-sym _q-bytes)]}

]}

]

More formats may be added in future versions of this library.

@history[
#:changed "1.1" @elem{Added @racket['OneAsymmetricKey], @racket['rkt-private],
and @racket['rkt-public] formats.}
#:changed "1.9" @elem{Added @racket['age/v1-public], @racket['age/v1-private],
and @racket['openssh-public] formats.}
]}

@defproc[(datum->pk-key [datum any/c]
                        [fmt symbol?]
                        [factories (or/c crypto-factory? (listof crypto-factory?))
                                   (crypto-factories)])
         pk-key?]{

Parses @racket[datum] and returns a PK key associated with an
implementation from @racket[factories]. If no implementation in
@racket[factories] supports @racket[fmt], an exception is raised.

See @racket[pk-key->datum] for information about the @racket[fmt]
argument.
}

@defproc[(pk-parameters->datum [pkp pk-parameters?]
                               [fmt symbol?])
         printable/c]{

Returns a datum representing the key parameters @racket[pkp], where
the encoding is selected by @racket[fmt]. Unless noted below, the
result is a bytestring (@racket[bytes?]). The following @racket[fmt]
options are supported:

@itemlist[

@item{@racket['AlgorithmIdentifier] --- DER-encoded
AlgorithmIdentifier @cite["PKIX"] representation of @racket[pkp]. All
key parameter types are supported, and an identifier for the key
parameter type is embedded in the encoding.

For @racket['dh] parameters, the PKCS #3 identifier and parameter
format @cite["PKCS3"] are used rather than those specified by
@cite["PKIX-AlgId"], for compatibility with OpenSSL.}

@item{@racket['DSAParameters] --- DER-encoded Dss-Parms @cite["PKIX-AlgId"]}

@item{@racket['DHParameter] --- DER-encoded DHParameter
@cite["PKCS3"]. Note: this format differs from the DomainParameters
format specified by PKIX.}

@item{@racket['EcpkParameters] --- DER-encoded EcpkParameters
@cite["PKIX-AlgId"] (called ECDomainParameters in @cite["SEC1"]).}

@item{@racket['rkt-params] --- An S-expression of one of the following forms:

@itemlist[

@item{@racket[(list 'dsa 'params _p _q _g)]}
@item{@racket[(list 'dh  'params _p _g)]}
@item{@racket[(list 'ec  'params _curve-oid)]}
@item{@racket[(list 'eddsa 'params _curve-sym)]}
@item{@racket[(list 'ecx 'params _curve-sym)]}

]}

]

More formats may be added in future versions of this library.

@history[#:changed "1.1" @elem{Added @racket['rkt-params] support.}]
}

@defproc[(datum->pk-parameters [datum any/c]
                               [fmt symbol?]
                               [factories (or/c crypto-factory? (listof crypto-factory?)) 
                                          (crypto-factories)])
         pk-parameters?]{

Parses @racket[datum] and returns a key-parameters value associated
with an implementation in @racket[factories]. If no implementation is
found that accepts @racket[fmt], an exception is raised.
}


@section[#:tag "pkcs8"]{PKCS #8 Encrypted Private Keys}

@defmodule[crypto/pkcs8]
@history[#:added "1.5"]

@deftogether[[
@defproc[(pkcs8-encrypt/pbkdf2-hmac
                        [password bytes?]
                        [pk (or/c private-key? bytes?)]
                        [#:digest digest-spec digest-spec? 'sha512]
                        [#:iterations iterations exact-positive-integer? (expt 2 16)]
                        [#:cipher cipher-spec cipher-spec? '(aes cbc)]
                        [#:key-size key-size exact-positive-integer?
                                    (cipher-default-key-size cipher-spec)])
         bytes?]
@defproc[(pkcs8-encrypt/scrypt
                        [password bytes?]
                        [pk (or/c private-key? bytes?)]
                        [#:N N exact-positive-integer? (expt 2 14)]
                        [#:r r exact-positive-integer? 8]
                        [#:p p exact-positive-integer? 1]
                        [#:cipher cipher-spec cipher-spec? '(aes cbc)]
                        [#:key-size key-size exact-positive-integer?
                                    (cipher-default-key-size cipher-spec)])
         bytes?]
]]{

Produce a DER-encoded EncryptedPrivateKeyInfo @cite["PKCS8"]
containing the private key @racket[pk] encrypted with a key derived
from @racket[password]. If @racket[pk] is a private key object
(@racket[private-key?]), it is converted to a byte string using
OneAsymmetricKey format. If @racket[pk] is a byte string, it should be
a OneAsymmetricKey or PrivateKeyInfo encoding, but the structure of
the byte string is not inspected.

See @racket[pbkdf2-hmac] for the meaning of the @racket[iterations]
argument, and see @racket[scrypt] for the meanings of the @racket[N],
@racket[r], and @racket[p] arguments.

The following values of @racket[cipher-spec] are currently supported:
@racket['(aes cbc)], @racket['(des-ede3 cbc)], @racket['(aes gcm)],
and @racket['(chacha20-poly1305 stream)].

The following values of @racket[digest-spec] are currently supported:
@racket['sha1], @racket['sha224], @racket['sha256], @racket['sha384],
and @racket['sha512].

Compatibility with OpenSSL 1.1.0 has been tested with @racket['(aes cbc)]
and @racket['(des-ede3 cbc)].
}

@defproc[(pkcs8-decrypt-bytes [password bytes?] [p8-epki bytes?]) bytes?]{

Decrypts the DER-encoded EncryptedPrivateKeyInfo @racket[p8-epki]
using @racket[password] and returns the unencrypted private key as a
byte string. The structure of the decrypted byte string is not inspected.

If the wrong password is given, then an exception will @emph{probably}
be raised, but for non-AEAD ciphers (such as AES-CBC), there is a
possibility that the decryption will succeed and return nonsense.
}

@defproc[(pkcs8-decrypt-key [password bytes?] [p8-epki bytes?]) private-key?]{

Decrypts the DER-encodedEncryptedPrivateKeyInfo @racket[p8-epki] using
@racket[password] and parses the unencrypted private key as
OneAsymmetricKey.

Equivalent to the following:
@racketblock[(datum->pk-key (pkcs8-decrypt-bytes password p8-epki) 'OneAsymmetricKey)]
}


@bibliography[
#:tag "pk-bibliography"

@bib-entry[#:key "AKP"
           #:title "RFC 5958: Asymmetric Key Packages"
           #:url "https://tools.ietf.org/html/rfc5958"]

@bib-entry[#:key "PKCS1"
           #:title "PKCS #1: RSA Cryptography, version 2.1"
           #:url "https://tools.ietf.org/html/rfc3447"]

@bib-entry[#:key "PKCS3"
           #:title "PKCS #3: Diffie-Hellman Key-Agreement Standard"]

@bib-entry[#:key "PKCS8"
           #:title "PKCS #8: Private-Key Information Syntax Specification, version 1.2"
           #:url "https://tools.ietf.org/html/rfc5208"]

@bib-entry[#:key "PKIX"
           #:title "RFC 5280: Internet X.509 Public Key Infrastructure: Certificate and CRL Profile"
           #:url "https://tools.ietf.org/html/rfc5280"]

@bib-entry[#:key "PKIX-AlgId"
           #:title "RFC 3279: Algorithms and Identifiers for the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile"
           #:url "https://tools.ietf.org/html/rfc3279"]

@bib-entry[#:key "PKIX-EdC"
           #:title "RFC 8410: Algorithm Identifiers for Ed25519, Ed448, X25519 and X448 for use in the Internet X.509 Public Key Infrastructure"
           #:url "https://tools.ietf.org/html/rfc8410"]

@bib-entry[#:key "RFC2631"
           #:title "RFC 2631: Diffie-Hellman Key Agreement Method"
           #:url "https://tools.ietf.org/html/rfc2631"]

@bib-entry[#:key "SEC1"
           #:title "SEC 1: Elliptic Curve Cryptography"
           #:url "http://www.secg.org/sec1-v2.pdf"]

@bib-entry[#:key "RFC7468"
           #:title "Textual Encodings of PKIX, PKCS, and CMS Structures"
           #:url "https://tools.ietf.org/html/rfc7468"]
]

