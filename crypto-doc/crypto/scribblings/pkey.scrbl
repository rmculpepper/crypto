#lang scribble/doc
@(require scribble/manual
          scribble/basic
          (for-label racket/base
                     racket/contract
                     crypto))

@title[#:tag "pkey"]{Public Key Cryptography}

@section{Algorithms and Keys}

A @scheme[<pkey>] is a first class object which captures public key algorithm 
details. Key-pairs can be generated using @scheme[generate-key] with a 
@scheme[<pkey>].

@deftogether[(
@defthing[pkey:rsa <pkey>]
@defthing[pkey:dsa <pkey>]
)]{
Builtin @scheme[<pkey>] algorithms.
}

@defproc[(!pkey? (o _)) boolean?]{
True if @scheme[o] is a @scheme[<pkey>].
}

@defproc[(pkey? (o _)) boolean?]{
True if @scheme[o] is a public or private key.
}

@defproc[(pkey-private? (o pkey?)) boolean?]{
True if @scheme[o] is a private key.
}

@defproc[(pkey->public-key (o pkey?)) pkey?]{
Extracts the public key component.
}

@deftogether[(
@defproc[(public-key->bytes (o pkey?)) bytes?]
@defproc[(private-key->bytes  (o pkey?)) bytes?]
@defproc[(bytes->public-key (bs bytes?)) pkey?]
@defproc[(bytes->private-key (bs bytes?)) pkey?]
)]{
Conversions between keys and bytes.
}

@deftogether[(
@defproc[(pkey-size (o pkey?)) exact-nonnegative-integer?]
@defproc[(pkey-bits (o pkey?)) exact-nonnegative-integer?]
)]{
The size of a key in bytes and bits respectively.
}

@defproc[(pkey=? (x pkey?) ...+) boolean?]{
Key equality predicate.
}

@section{Signatures}

@defproc[(sign (pk pkey?) (t <digest>) (data (or bytes? input-port?)))
          bytes?]{
Computes a signature, using the @emph{private} key @scheme[pk] and @scheme[t]
as the digest type.

@bold{Note}: As of openssl-0.9.8 only certain types of digests can be used
with specific public key algorithms. Specifically, @scheme[pkey:rsa] keys
can only sign using @scheme[sha*] and @scheme[ripemd160] as digests, 
while @scheme[pkey:dsa] can only sign with @scheme[dss1] digests.

This restriction has been removed in development versions of openssl (0.9.9).
}

@defproc[(verify (pk pkey?) (t <digest>) (sig bytes?) (data (or bytes? input-port?)))
         boolean?]{
Verifies a signature @scheme[sig], using the @emph{public} key @scheme[pk] and
@scheme[t] as the digest type.
}

@deftogether[(
@defproc*[(
[(digest-sign (dg digest?) (pk pkey?)) bytes?]
[(digest-sign (dg digest?) (pk pkey?) (bs bytes?) 
              (start exact-nonnegative-integer? 0)
              (end exact-nonnegative-integer? (bytes-length bs)))
 exact-nonnegative-integer?]
)]
@defproc[(digest-verify (dg digest?) (pk pkey?) (bs bytes?)
                        (start exact-nonnegative-integer? 0)
                        (end exact-nonnegative-integer? (bytes-length bs)))
          boolean?]
)]{
Signature and verification using digest contexts directly.
}

@section{Encryption}

@deftogether[(
@defproc[(encrypt/pkey (pk pkey?) (data bytes?)
                       (start exact-nonnegative-integer? 0)
                       (end exact-nonnegative-integer? (bytes-length data)))
          bytes?]
@defproc[(decrypt/pkey (pk pkey?) (data bytes?)
                       (start exact-nonnegative-integer? 0)
                       (end exact-nonnegative-integer? (bytes-length data)))
          bytes?]
)]{
Encrypt and decrypt using a public/private key.
}

@defproc[(encrypt/envelope (pk pkey?) (c <cipher>) (arg _) ...)
         (values bytes? bytes? _ ...)]{
Encrypt using @scheme[c] as the @scheme[<cipher>] with a random key
sealed using the @emph{public} key @scheme[pkey].

Returns the sealed key and iv for the cipher, prepended to the values
returned by the nested @scheme[encrypt].
}

@defproc[(decrypt/envelope (pk pkey?) (c <cipher>) (sk bytes?) (iv bytes?)
          (arg _) ...)
         (values _ ...)]{
Decrypt using @scheme[c] as the @scheme[<cipher>], using the 
sealed key @scheme[sk] decrypted with the @emph{private} key @scheme[pk].
}
