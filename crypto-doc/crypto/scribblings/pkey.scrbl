#lang scribble/doc
@(require scribble/manual
          scribble/basic
          racket/list
          crypto/private/common/catalog
          (for-label racket/base
                     racket/contract
                     crypto))

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


@section[#:tag "pk-admin"]{Administrative PK Functions}

@defproc[(pk-spec? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is a PK cryptosystem specifier,
@racket[#f] otherwise.

A PK cryptosystem specifier is one of the following: @racket['rsa],
@racket['dsa], @racket['dh], or @racket['ec]. Strictly speaking, it
specifies the information represented by the public and private keys
and the algorithms that operate on that information. For example,
@racket['rsa] specifies RSA keys with RSAES-* encryption algorithms
and the RSASSA-* signature algorithms, and @racket['ec] specifies EC
keys with ECDSA signing and ECDH key agreement.
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

@defproc[(pk-key->parameters [pk pk-key?]) pk-parameters?]{

Returns a value representing the key parameters of @racket[pk], or
@racket[#f] if @racket[pk]'s cryptosystem does not use key parameters.
}

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
using the given configuration options. Unless otherwise specified, the
configuration values are optional, and the default values are
implementation-dependent.

The following configuration values are recognized for DSA
(@racket['dsa]):
@itemlist[

@item{@racket[(list 'nbits _nbits)] --- Generate a prime modulus of
size @racket[_nbits]. Examples include @racket[1024] and
@racket[2048].}

]

The following configuration values are recognized for DH
(@racket['dh]): 
@itemlist[

@item{@racket[(list 'nbits _nbits)] --- Generate a prime modulus of
size @racket[_nbits]. Examples include @racket[1024] and
@racket[2048].}

@item{@racket[(list 'generator _generator)] --- Use the given
@racket[_generator]; must be either @racket[2] or @racket[5].}

]

The following configuration values are recognized for EC
(@racket['ec]):
@itemlist[

@item{@racket[(list 'curve _curve-name)] --- Required. Use the
standard curve named @racket[_curve-name]. Examples include
@racket["NIST P-256"] and @racket["secp192r1"].}

]
}

@defproc[(generate-private-key [pki (or/c pk-spec? pk-impl? pk-parameters?)]
                               [keygen-config (listof (list/c symbol? any/c)) '()])
         private-key?]{

Generate a private key from the given PK implementation or PK
parameters. Unless otherwise specified, configuration values are
optional, and the default values are implementation dependent.

The following configuration values are recognized for RSA
(@racket['rsa]):
@itemlist[

@item{@racket[(list 'nbits _nbits)] --- Generate a modulus of size
@racket[_nbits]. Examples include @racket[1024] and @racket[2048].}

]
}


@section[#:tag "pk-sign"]{PK Signatures}

In PK signing, the sender uses their own private key to sign a
message; any other party can verify the sender's signature using the
sender's public key. Only short messages can be directly signed using
PK cryptosystems (limits are generally proportional to the size of the
PK keys), so a typical process is to compute a digest of the message
and sign the digest. The message and digest signature are sent
together, possibly with additional data. PK signing and verification
is supported by the RSA, DSA, and EC (ECDSA) cryptosystems.

@defproc[(pk-sign-digest [pk private-key?]
                         [di (or/c digest-spec? digest-impl?)]
                         [dgst bytes?]
                         [#:pad padding (or/c #f 'pkcs1-v1.5 'pss) #f])
         bytes?]{

Returns the signature using the private key @racket[pk] of
@racket[dgst] and metadata indicating that @racket[dgst] was computed
using digest function @racket[di]. The @racket[dgst] argument should
be the @racket[di] digest of some message.

If @racket[pk] is an RSA private key, then @racket[padding] selects
between PKCS#1-v1.5 and PSS @cite{PKCS1}. If @racket[padding] is
@racket[#f], then an implementation-dependent mode is chosen. For all
other cryptosystems, @racket[padding] must be @racket[#f].

If @racket[di] is not a digest compatible with @racket[pk], or if the
size of @racket[dgst] is not the digest size of @racket[di], or if the
digest size is too large for @racket[pk], then an exception is raised.
}

@defproc[(pk-verify-digest [pk pk-key?]
                           [di (or/c digest-spec? digest-impl?)] 
                           [dgst bytes?]
                           [sig bytes?]
                           [#:pad padding (or/c #f 'pkcs1-v1.5 'pss) #f])
         boolean?]{

Returns @racket[#t] if @racket[pk] verifies that @racket[sig] is a
valid signature of the message digest @racket[dgst] using digest
function @racket[di], or @racket[#f] if the signature is invalid.
}

@deftogether[[
@defproc[(digest/sign [pk private-key?]
                      [di (or/c digest-spec? digest-impl?)]
                      [input (or/c bytes? string? input-port?)]
                      [#:pad padding (or/c #f 'pkcs1-v1.5 'pss) #f])
         bytes?]
@defproc[(digest/verify [pk pk-key?]
                        [di (or/c digest-spec? digest-impl?)]
                        [input (or/c bytes? string? input-port?)]
                        [sig bytes?]
                        [#:pad padding (or/c #f 'pkcs1-v1.5 'pss) #f])
         boolean?]
]]{

Computes or verifies signature of the @racket[di] message digest of
@racket[input]; equivalent to calling @racket[digest] then
@racket[pk-sign-digest] or @racket[pk-verify-digest], respectively.
}


@section[#:tag "pk-encrypt"]{PK Encryption}

In PK encryption, the sender uses the public key of the intented
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

In PK key agreement (sometimes called key exchange) two parties derive
a shared secret by exchanging public keys. Each party can compute the
secret from their own private key and the other's public key, but it
is believed infeasible for an observer to compute the secret from the
two public keys alone. PK secret derivation is supported by the DH and
ECDH cryptosystems.

@defproc[(pk-derive-secret [pk private-key?]
                           [peer-pk (or/c pk-key? bytes?)])
         bytes?]{

Returns the shared secret derived from the private key @racket[pk] and
the public key @racket[peer-pk]. If @racket[peer-pk] is a PK key, it
must be a key belonging to the same cryptosystem and implementation as
@racket[pk]; otherwise an exception is raised. If @racket[peer-pk] is
a bytestring, an exception is raised if it cannot be interpreted as
public key data.

Note that the derived secret is a deterministic function of the
private keys: if two parties perform secret derivation twice, they
will produce the same secret both times. In addition, the secret is
not uniformly distributed. For these reasons, the derived secret
should not be used directly as a key; instead, it should be used to
generate key material using a process such as described in RFC 2631
@cite{RFC2631}.
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
identifier and parameters @cite["PKCS3"] rather than those specified
by @cite["PKIX-AlgId"].}

@item{@racket['PrivateKeyInfo] --- DER-encoded PrivateKeyInfo
@cite["PKCS8"] representation of @racket[pk], which must be a private
key. All key types are supported, and an identifier for the key type
is embedded in the encoding.}

@item{@racket['RSAPrivateKey] --- DER-encoded RSAPrivateKey
@cite["PKCS1"] representation of @racket[pk], which must be an RSA
private key.}

@;{@item{@racket['DSAPrivateKey] --- DER-encoded representation of
@racket[pk], which must be a DSA private key, in a non-standard format
used by OpenSSL.}}

@item{@racket['ECPrivateKey] --- DER-encoded ECPrivateKey @cite{SEC1}
representation of @racket[pk], which must be an EC private key. Only
keys using named curves are supported.}

]

More formats may be added in future versions of this library.
}

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

For compatibility with OpenSSL, the PKCS #3 identifier and parameter
format @cite["PKCS3"] are used rather than those specified by
@cite["PKIX-AlgId"].}

@item{@racket['DSAParameters] --- DER-encoded Dss-Parms @cite["PKIX-AlgId"]}

@item{@racket['DHParameter] --- DER-encoded DHParameter
@cite["PKCS3"]. Note: this format differs from the DomainParameters
format specified by PKIX.}

@item{@racket['EcpkParameters] --- DER-encoded EcpkParameters
@cite["PKIX-AlgId"] (called ECDomainParameters in @cite["SEC1"]).}

]

More formats may be added in future versions of this library.
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
        

@bibliography[
#:tag "pk-bibliography"

@bib-entry[#:key "PKCS1"
           #:title "PKCS #1: RSA Cryptography, version 2.1"
           #:url "http://www.ietf.org/rfc/rfc3447.txt"]

@bib-entry[#:key "PKCS3"
           #:title "PKCS #3: Diffie-Hellman Key-Agreement Standard"
           #:url "http://www.emc.com/emc-plus/rsa-labs/standards-initiatives/pkcs-3-diffie-hellman-key-agreement-standar.htm"]

@bib-entry[#:key "PKCS8"
           #:title "PKCS #8: Private-Key Information Syntax Specification, version 1.2"
           #:url "http://www.ietf.org/rfc/rfc5208.txt"]

@bib-entry[#:key "PKIX"
           #:title "RFC 3280: Internet X.509 Public Key Infrastructure: Certificate and CRL Profile"
           #:url "http://www.ietf.org/rfc/rfc3280.txt"]

@bib-entry[#:key "PKIX-AlgId"
           #:title "RFC 3279: Algorithms and Identifiers for the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile"
           #:url "http://www.ietf.org/rfc/rfc3279.txt"]

@bib-entry[#:key "RFC2631"
           #:title "RFC 2631: Diffie-Hellman Key Agreement Method"
           #:url "http://www.ietf.org/rfc/rfc2631.txt"]

@bib-entry[#:key "SEC1"
           #:title "SEC 1: Elliptic Curve Cryptography"
           #:url "http://www.secg.org/download/aid-780/sec1-v2.pdf"]
]
