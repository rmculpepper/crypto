#lang scribble/doc
@(require scribble/manual
          scribble/basic
          racket/list
          (for-label racket/base
                     racket/contract
                     racket/random
                     crypto))

@title[#:tag "misc"]{Miscellaneous Notes}

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
