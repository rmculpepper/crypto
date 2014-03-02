#lang scribble/doc
@(require scribble/manual
          scribble/basic
          (for-label racket/base
                     racket/contract
                     crypto))

@title[#:tag "random"]{Randomness}

Many cryptographic operations require a source of random numbers (or,
equivalently, random bytestrings). In many environments, truly random
numbers are impossible to obtain in sufficient quantity, so
pseudo-random number generators designed for unpredictability and
robustness to state compromise are used instead. A suitable source of
pseudo-random numbers is called a cryptographically secure
pseudo-random number generator (CSPRNG).

Note that ordinary pseudo-random number generators like Racket's
@racket[random] function are @bold{not} cryptographically secure. A
CSPRNG that is improperly seeded (initialized), such as from a
low-entropy source such as the current timestamp, is @bold{not}
cryptographically secure. See the notes on CSPRNG initialization in
@seclink["factory"] for more information.


@defproc[(random-impl? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is an implementation of a CSPRNG,
@racket[#f] otherwise.
}

@defproc[(get-random [factories (or/c crypto-factory? (listof crypto-factory?))
                                (crypto-factories)])
         random-impl?]{

Returns an implementation of a CSPRNG from @racket[factories], or
@racket[#f] if no factory in @racket[factories] provides a CSPRNG
implementation.
}

@defproc[(random-bytes [n exact-nonnegative-integer?]
                       [ri random-impl? (get-random)]
                       [#:level level (or/c 'strong 'very-strong) 'strong])
         bytes?]{

Generates @racket[n] random bytes using the CSPRNG @racket[ri].

Some CSPRNGs may use the @racket[level] argument to select the
strength of the random numbers produced. The level @racket['strong] is
used to request material for use as nonces, random padding, IVs, and
key material; the level @racket['very-strong] is used to request
long-term key material. However, a CSPRNG implementation may ignore
the @racket[level] argument, using the same process for all randomness
requests.
}


@bibliography[
#:tag "random-bibliography"

@bib-entry[#:key "RFC4086"
           #:title "RFC 4086: Randomness Requirements for Security"
           #:url "http://www.ietf.org/rfc/rfc4086.txt"]

]
