#lang scribble/doc
@(require scribble/manual
          scribble/basic
          racket/list
          (for-label racket/base
                     racket/contract
                     racket/random
                     crypto))

@(module racket-links racket/base
   (require scribble/manual (for-label racket/random))
   (define racket:crypto-random-bytes-id @racket[crypto-random-bytes])
   (provide racket:crypto-random-bytes-id))
@(require (submod "." racket-links))

@title[#:tag "misc"]{Miscellaneous Notes and Utilities}

@; ------------------------------------------------------------
@section[#:tag "input"]{Input to Cryptographic Operations}

@defthing[input/c contract?]{

Contract for valid input data to an operation such as @racket[digest],
@racket[encrypt], etc. The operations are defined in terms of bytestrings, but
other values are accepted and converted as following:
@itemlist[
@item{@racket[bytes?] --- no conversion needed}
@item{@racket[string?] --- converted to bytes via @racket[string->bytes/utf-8]}
@item{@racket[input-port?] --- read until @racket[eof] is returned (but the port
is not closed)}
@item{@racket[bytes-range?] --- represents a subsequence of a bytestring}
@item{@racket[(listof input/c)] --- concatenation of the input elements}
]
Note that fixed-sized data such as keys, IVs, etc are not represented as
@racket[input/c].
}

@defstruct*[bytes-range
            ([bs bytes?]
             [start exact-nonnegative-integer?]
             [end exact-nonnegative-integer?])]{

Represents a subsequence of a bytestring. See also @racket[input/c].

Equivalent to @racket[(subbytes bs start end)] if @racket[bs] is not
subsequently mutated, but avoids making a copy.
}

@; ------------------------------------------------------------
@section[#:tag "crypto-random-bytes"]{Random Bytes}

@(declare-exporting crypto)

@defproc[(crypto-random-bytes [n exact-nonnegative-integer?]) bytes?]{

For convenience, this library re-exports @racket:crypto-random-bytes-id
from @racketmodname[racket/random].
}

@; ------------------------------------------------------------
@section[#:tag "pem"]{PEM Reading}

@defmodule[crypto/pem]

@history[#:added "1.7"]

@defproc[(read-pem [in input-port?]
                   [decode (-> bytes? any/c) base64-decode]
                   [#:only only-kinds (or/c #f (listof bytes?)) #f])
         (or/c (cons/c bytes? any/c) eof)]{

Reads a single PEM-encapsulated datum from @racket[in], decodes it
using @racket[decode], and returns a pair containing the encapulation
boundary label and the decoded result. Data before the starting
encapsulation boundary is discarded. If no starting encapsulation
boundary is found before the end of input, @racket[eof] is
returned. If the ending encapsulation boundary is missing or has the
wrong label, an error is raised.

For example, the encapsulation boundaries for an X.509 certificate are
lines consisting of @racket[#"-----BEGIN CERTIFICATE-----"] and
@racket[#"-----END CERTIFICATE-----"], and the label returned is
@racket[#"CERTIFICATE"].

Note: This format is the PEM-based ``textual encoding''
@cite["RFC7468"] used for encoding cryptographic keys, certificates,
etc. It is commonly called ``PEM'' although it is not completely
compatible with the original PEM format.
}

@; ------------------------------------------------------------
@section[#:tag "provider-notes"]{Notes on Cryptography Providers}

@subsection[#:tag "random"]{CSPRNG Initialization}

Some cryptographic operations require a source of cryptographically
secure pseudo-random numbers. Some of these, such as
@racket[generate-cipher-key], are handled at the Racket level and use
@racket[crypto-random-bytes]. Other operations, such as
@racket[generate-private-key], RSA signing with PSS padding, and many
more, use the crypto provider's internal CSPRNG. This section contains
notes on crypto providers' CSPRNG initialization.

@bold{libcrypto} The libcrypto foreign library automatically seeds its
CSPRNG using entropy obtained from the operating system
(@hyperlink["http://wiki.openssl.org/index.php/Random_Numbers"]{as
described here}).

@bold{gcrypt} The libgcrypt foreign library seems to perform some
default CSPRNG initialization, but I don't know the details.

@bold{nettle} The @racketmodname[crypto] library creates a Yarrow-256
instance and seeds it with entropy obtained from
@racket[crypto-random-bytes]. The instance is reseeded when a certain
number of entropy-consuming operations have been performed since the
last reseed.

@history[#:changed "1.2" @elem{The @racketmodname[crypto] module now
also re-exports @racket[crypto-random-bytes] from
@racketmodname[racket/random].}]


@subsection[#:tag "libcrypto-notes"]{Libcrypto Quirks}

PSS padding for RSA signatures is, in principle, parameterized by the
salt length. A standard choice is the length of the digest to be
signed. By default, libcrypto uses the maximum possible salt length
when signing and infers the salt length when verifying, as documented
for @hyperlink["https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_CTX_set_rsa_pss_saltlen.html"]{EVP_PKEY_CTX_set_rsa_pss_saltlen}.
See also @hyperlink["https://crypto.stackexchange.com/questions/1217/rsa-pss-salt-size"]{this
discussion}. Unfortunately, other libraries do not directly support this behavior and it is nontrivial to work around it.
Thus for greater compatibility, this library defines @racket['pss]
padding to use the digest length and @racket['pss*] to be the
libcrypto-specific behavior.


@subsection[#:tag "gcrypt-notes"]{GCrypt Quirks}

If ECDSA is used with a digest longer than the bit-length of the
curve, gcrypt either fails to correctly truncate the digest or
otherwise handles it by default in a way incompatible with libcrypto
and nettle. Consequently, this library truncates the digest before
passing it to gcrypt for signing.
@; {https://crypto.stackexchange.com/questions/18488/ecdsa-with-sha256-and-sepc192r1-curve-impossible-or-how-to-calculate-e}

GCrypt does not expose operations to compute EC and EdDSA public keys
from the private keys, so reading a private key in PrivateKeyInfo or
OneAsymmetricKey form may fail if the optional public key field is
missing.


@subsection[#:tag "sodium-notes"]{Sodium Quirks}

Sodium provides only ``all-at-once'' encryption and decryption
functions. Consequently, encryption and decryption contexts using
sodium ciphers produce no output until @racket[cipher-final] is
called.

@; ------------------------------------------------------------
@section[#:tag "security-level"]{Security Strength Levels}

@defthing[security-strength/c contract? #:value exact-nonnegative-integer?]{

Represents the estimated @deftech{security strength}, measured in
bits, of a cryptographic primitive. The strength rating of primitives
generally follows the guidelines specified by
@hyperlink["https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final"]{NIST
SP 800-57 Part 1 (Section 5.6: Guidance for Cryptographic Algorithm
and Key-Size Selection)}. See also @racket[security-level/c].

@bold{Note: } The security strength of a cryptographic primitive is generally
not the same as its key size or its output size. Furthermore, reasoning in terms
of security bits requires considering all parts of a system: for example, if a
message has only 20 bits of entropy, then taking the SHA-512 of it still only
has 20 bits of entropy.

@history[#:added "1.8"]}

@defthing[security-level/c contract? #:value (integer-in 0 5)]{

Represents a @deftech{security level} comparable to an
@hyperlink["https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_security_level.html"]{OpenSSL
security level}. The levels correspond to the ranges of @tech{security strength}
ratings as follows:

@nested[
@tabular[
#:sep @hspace[4]
#:column-properties '(center left left)
(list
 (list @bold{Level} @bold{Bits}             @bold{Includes*})
 (list @elem{0}     @elem{< 80}             @elem{SHA-1})
 (list @elem{1}     @elem{≥ 80 but < 112}   @elem{RSA≥1024, ECC≥160})
 (list @elem{2}     @elem{≥ 112 but < 128}  @elem{RSA≥2048, ECC≥224, SHA-224})
 (list @elem{3}     @elem{≥ 128 but < 192}  @elem{RSA≥3072, ECC≥256, SHA-256})
 (list @elem{4}     @elem{≥ 192 but < 256}  @elem{RSA≥7680, ECC≥384, SHA-384})
 (list @elem{5}     @elem{≥ 256}            @elem{RSA≥15360, ECC≥512, SHA-512})
)]]
The ``Includes'' column is incomplete and imprecise. For example, SHA-256 is
rated at 128 bits of security in contexts where collision resistance is required
(for example, in a digital signature) but 256 bits when it is not (for example,
with HMAC).

@history[#:added "1.8"]}

@defproc[(security-level->strength [level security-level/c])
         security-strength/c]{

Converts a @tech{security level} to the minimum value of its @tech{security
strength} range.

@history[#:added "1.8"]}

@defproc[(security-strength->level [strength security-strength/c])
         security-level/c]{

Converts a @tech{security strength} rating to the @tech{security level} that
contains it.

@history[#:added "1.8"]}
