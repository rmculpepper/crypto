#lang scribble/doc
@(require scribble/manual
          scribble/basic
          scribble/example
          racket/runtime-path
          (for-label racket/base
                     racket/contract
                     racket/random
                     crypto
                     crypto/pem
                     crypto/age
                     crypto/util/bech32))

@(module racket-links racket/base
   (require scribble/manual (for-label racket/random))
   (define racket:crypto-random-bytes-id @racket[crypto-random-bytes])
   (provide racket:crypto-random-bytes-id))
@(require (submod "." racket-links))

@(define-runtime-path log-file "eval-logs/util.rktd")
@(define the-eval (make-log-based-eval log-file 'replay))
@(the-eval '(require crypto crypto/util/bech32))

@title[#:tag "util"]{Miscellaneous Utilities}

@; ------------------------------------------------------------
@section[#:tag "main-util"]{Main Utilities}

The utilities in this section are provided by the main @racketmodname[crypto]
module.

@; ----------------------------------------
@subsection[#:tag "input"]{Input to Cryptographic Operations}

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

@; ----------------------------------------
@subsection[#:tag "crypto-random-bytes"]{Random Bytes}

@(declare-exporting crypto)

@defproc[(crypto-random-bytes [n exact-nonnegative-integer?]) bytes?]{

For convenience, this library re-exports @racket:crypto-random-bytes-id
from @racketmodname[racket/random].
}

@; ----------------------------------------
@subsection[#:tag "security-level"]{Security Strength Levels}

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
@section[#:tag "bech32"]{Bech32 Encoding and Decoding}

@defmodule[crypto/util/bech32]

@history[#:added "1.9"]

This module implements an encoder and decoder for the
@hyperlink["https://en.bitcoin.it/wiki/Bech32"]{Bech32} format, which
is used by the @hyperlink["https://github.com/FiloSottile/age"]{age
encryption tool} to encode X25519 public and private keys. 

@defproc[(bech32-encode [hrp string?] [data bytes?]) string?]{

Encodes the ``human-readable part'' (@racket[hrp]) with the given
@racket[data]. If @racket[hrp] contains disallowed characters, or if
the result would be longer than 90 characters, an exception is raised.

@examples[#:eval the-eval
(bech32-encode "age" #"1234567890abcdef1234567890UVWXYZ")
]}

@defproc[(bech32-decode [s string?]) (list/c string? bytes?)]{

Decodes the Bech32 string @racket[s], producing a ``human-readable
part'' string and a data byte string.

If @racket[s] is not a well-formed Bech32 string, an exception is
raised. In particular, @racket[s] must be between 8 and 90 characters
long, it must not contain a mixture of lowercase and uppercase
letters, and it must end with a valid checksum.

@examples[#:eval the-eval
(bech32-decode "age1xyerxdp4xcmnswfsv93xxer9vccnyve5x5mrwwpexp24v46ct9dq3wvnf4")
(eval:error (bech32-decode "age1xyerxdp4xcmnswfsv93xxer9vccnyve5x5mrwwpexp24v46ct9dq3wvnf"))
]}

@; ------------------------------------------------------------
@section[#:tag "age"]{age Encryption}

@defmodule[crypto/age]

@history[#:added "1.9"]

@(define age-spec "https://age-encryption.org/v1")
@(define age-tool "https://github.com/FiloSottile/age")

Implementation of @hyperlink[age-spec]{age-encryption.org/v1}, compatible with
the @hyperlink[age-tool]{age encryption tool}.

X25519 keys can be imported and exported in @hyperlink[age-tool]{age}-compatible
format using @racket[pk-key->datum] and @racket[datum->pk-key] with the
@racket['age/v1-public] and @racket['age/v1-private] format symbols.

@defproc[(age-encrypt [recips (listof (or/c pk-key? (list/c 'scrypt bytes?)))]
                      [data (or/c input-port? bytes?)])
         bytes?]{

Encrypts @racket[data] to each recipient in @racket[recips]. Each
recipient must be either an X25519 public key (@racket[pk-key?]) or
@racket[(list 'scrypt _passphrase)].
}

@defproc[(age-decrypt [idents (listof (or/c private-key? bytes?))]
                      [enc-data (or/c input-port? bytes?)])
         bytes?]{

Decrypts @racket[enc-data] using one of the identities listed in
@racket[idents]. Each identity must be either an X25519 private key
(@racket[private-key?]) or a byte string @racket[_passphrase].

If decryption fails, an exception is raised.
}

@; ------------------------------------------------------------
@(close-eval the-eval)
