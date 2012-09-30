#lang scribble/doc
@(require scribble/manual
          scribble/basic
          planet/scribble
          (for-label racket/base
                     racket/contract
                     (this-package-in main)))

@title[#:tag "util"]{Utilities}

@section{Key Generation}

@defproc*[(
[(generate-key (t <cipher>)) (values bytes? bytes?)]
[(generate-key (t <pkey>) (bits exact-nonnegative-integer?) (arg _) ...) 
         pkey?]
[(generate-key (t <digest>)) bytes?]
[(generate-key (t <dh>)) (values dhkey? bytes?)]
)]{
Random key generation.

When @scheme[t] is a @scheme[<cipher>] instance the returned values are 
a fresh key and iv for the algorithm.

When @scheme[t] is a @scheme[<pkey>] instance the @scheme[bits] argument 
specifies the size of the requested key and the returned value is a fresh @scheme[pkey]. 
For @scheme[pkey:rsa] the function optionally accepts an exponent argument 
(defaults to 65537).

When @scheme[t] is a @scheme[<digest>] instance, a fresh key for hmac is 
created.

Finally, when @scheme[t] is a @scheme[<dh>] instance the returned values are
the private @scheme[dh] key and the public key part for the exchange.
}

@section{Randomness}

@deftogether[(
@defproc[(random-bytes (len exact-nonnegative-integer?)) bytes?]
@defproc[(random-bytes! (o bytes?) 
                        (start exact-nonnegative-integer? 0)
                        (end exact-nonnegative-integer? (bytes-length o)))
         bytes?]
)]{
Generate cryptographically secure random data.
}

@deftogether[(
@defproc[(pseudo-random-bytes (len exact-nonnegative-integer?)) bytes?]
@defproc[(pseudo-random-bytes! (o bytes?) 
                               (start exact-nonnegative-integer? 0)
                               (end exact-nonnegative-integer? (bytes-length o)))
         bytes?]
)]{
Generate pseudorandom data (not cryptographically secure).
}

@deftogether[(
@defproc[(random-rnd-status) boolean?]
@defproc[(random-rnd-add (o bytes?)) _]
@defproc[(random-rnd-seed (o bytes?)) _]
@defproc[(random-rnd-read (f path) (len exact-nonnegative-integer?))
         integer?]
@defproc[(random-rnd-write (f path)) integer?]
@defproc[(random-rnd-filename) path?]
)]{
Query and manipulate the random entropy pool.

In general, you should not have to use these functions directly as libcrypto
automatically refreshes the entropy pool using OS-provided cryptographic 
facilities.
}


@section{Engine Support}

@deftogether[(
@defproc[(engine-load-builtin) _]
@defproc[(engine-cleanup) _]
)]{
@scheme[engine-load-builtin] loads the builtin accelerated libcrypto engine 
implementations. 

The application must cleanup by explicitly calling @scheme[engine-cleanup] 
as there is currently no reliable way to automatically cleanup using ffi.
}

@section{Miscellaneous}
@defmodule*/no-declare[(crypto/util (planet vyzo/crypto/util))]
@declare-exporting{util.ss}

This module provides some additional utilities that are not exported
by the main crypto library.

@deftogether[(
@defproc[(hex (o bytes?)) bytes?]
@defproc[(unhex (o bytes)) bytes?]
)]{
hex-encode and decode a byte-string
}

@deftogether[(
@defproc[(bytes-xor (in bytes?) (key bytes?)) bytes?]
@defproc[(bytes-xor! (in bytes?) (key bytes?)) bytes?]
)]{
Compute the bitwise-xor of two byte-strings;
@scheme[bytes-xor!] computes the result in-place by mutating @scheme[in].

@scheme[key] must be at least as long as @scheme[in].
}

@defproc[(shrink-bytes (o bytes?) (len exact-nonnegative-integer?)) bytes?]{
Returns @scheme[(subbytes o len)] when @scheme[o] is longer than @scheme[len]
and  @scheme[o] otherwise.
}
