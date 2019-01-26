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

@section[#:tag "crypto-random-bytes"]{Random Bytes}

@(declare-exporting crypto)

@defproc[(crypto-random-bytes [n exact-nonnegative-integer?]) bytes?]{

For convenience, this library re-exports @racket:crypto-random-bytes-id
from @racketmodname[racket/random].
}

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
