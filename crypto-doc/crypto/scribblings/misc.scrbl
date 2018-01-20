#lang scribble/doc
@(require scribble/manual
          scribble/basic
          scribble/eval
          racket/list
          crypto/private/common/catalog
          (for-label racket/base
                     racket/contract
                     racket/random
                     crypto))

@(define the-eval (make-base-eval))
@(the-eval '(require crypto crypto/libcrypto))
@(the-eval '(crypto-factories (list libcrypto-factory)))

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

@(close-eval the-eval)
