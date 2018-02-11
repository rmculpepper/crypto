#lang scribble/doc
@(require scribble/manual
          scribble/basic
          scribble/eval
          racket/list
          racket/runtime-path
          crypto/private/common/catalog
          (for-label racket/base
                     racket/contract
                     racket/random
                     crypto))

@(define-runtime-path log-file "eval-logs/digest.rktd")
@(define the-eval (make-log-based-eval log-file 'replay))
@(the-eval '(require crypto crypto/libcrypto))
@(the-eval '(crypto-factories (list libcrypto-factory)))

@title[#:tag "digest"]{Message Digests}

A message digest function (sometimes called a cryptographic hash
function) maps variable-length, potentially long messages to
fixed-length, relatively short digests. Different digest functions, or
algorithms, compute digests of different sizes and have different
characteristics that may affect their security.

The HMAC construction combines a digest function together with a
secret key to form an authenticity and integrity mechanism
@cite{HMAC}.

This library provides both high-level, all-at-once digest operations
and low-level, incremental operations.

@defproc[(digest-spec? [v any/c]) boolean?]{

Returns @racket[#f] if @racket[v] represents a digest
specifier, @racket[#f] otherwise.

A digest specifier is a symbol, which is interpreted as the name of a
digest. The following symbols are valid:
@(let ([digest-names (sort (hash-keys known-digests) symbol<?)])
   (add-between (for/list ([digest-name digest-names])
                  (racket '#,(racketvalfont (format "~a" digest-name))))
                ", ")).
Not every digest name in the list above necessarily has an available
implementation, depending on the cryptography providers installed.

Future versions of this library may add other forms of digest
specifiers.
}

@defproc[(digest-impl? [v any/c]) boolean?]{

Returns @racket[#f] if @racket[v] represents a digest implementation,
@racket[#f] otherwise.
}

@defproc[(get-digest [di digest-spec?]
                     [factories (or/c crypto-factory? (listof crypto-factory?))
                                (crypto-factories)])
         (or/c digest-impl? #f)]{

Returns an implementation of digest @racket[di] from the given
@racket[factories]. If no factory in @racket[factories] implements
@racket[di], returns @racket[#f].
}

@defproc[(digest-size [di (or/c digest-spec? digest-impl? digest-ctx?)])
         exact-positive-integer?]{

Returns the size in bytes of the digest computed by the algorithm
represented by @racket[di].

@examples[#:eval the-eval
(digest-size 'sha1)
(digest-size 'sha256)
]
}

@defproc[(digest-block-size [di (or/c digest-spec? digest-impl? digest-ctx?)])
         exact-positive-integer?]{

Returns the size in bytes of the digest's internal block size. This
information is usually not needed by applications, but some
constructions (such as HMAC) are defined in terms of a digest
function's block size.

@examples[#:eval the-eval
(digest-block-size 'sha1)
]
}

@defproc[(generate-hmac-key [di (or/c digest-spec? digest-impl?)])
         bytes?]{

Generate a random secret key appropriate for HMAC using digest
@racket[di]. The length of the key is @racket[(digest-size di)].

The random bytes are generated with @racket[crypto-random-bytes].
}


@section{High-level Digest Functions}

@defproc[(digest [di (or/c digest-spec? digest-impl?)]
                 [input input/c])
         bytes?]{

Computes the digest of @racket[input] using the digest function
represented by @racket[di]. See @racket[input/c] for accepted values
and their conversion rules to bytes.

@examples[#:eval the-eval
(digest 'sha1 "Hello world!")
(digest 'sha256 "Hello world!")
]
}

@defproc[(hmac [di (or/c digest-spec? digest-impl?)]
               [key bytes?]
               [input input/c])
         bytes?]{

Like @racket[digest], but computes the HMAC of @racket[input] using
digest @racket[di] and the secret key @racket[key]. The @racket[key]
may be of any length, but @racket[(digest-size di)] is a typical
key length @cite{HMAC}.
}

@section{Low-level Digest Functions}

@defproc[(make-digest-ctx [di (or/c digest-spec? digest-impl?)])
         digest-ctx?]{

Creates a digest context for the digest function represented by
@racket[di]. A digest context can be incrementally updated with
message data.

@examples[#:eval the-eval
(define dctx (make-digest-ctx 'sha1))
(digest-update dctx "Hello ")
(digest-update dctx "world!")
(digest-final dctx)
]
}

@defproc[(digest-ctx? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is a digest context, @racket[#f]
otherwise.
}

@defproc[(digest-update [dctx digest-ctx?]
                        [input input/c])
         void?]{

Updates @racket[dctx] with the message data corresponding to
@racket[input]. The @racket[digest-update] function can be called
multiple times, in which case @racket[dctx] computes the digest of the
concatenated inputs.
}

@defproc[(digest-final [dctx digest-ctx?])
         bytes?]{

Returns the digest of the message accumulated in @racket[dctx] so far
and closes @racket[dctx]. Once @racket[dctx] is closed, any further
operation performed on it will raise an exception.
}

@defproc[(digest-copy [dctx digest-ctx?])
         (or/c digest-ctx? #f)]{

Returns a copy of @racket[dctx], or @racket[#f] is the implementation
does not support copying. Use @racket[digest-copy] (or
@racket[digest-peek-final]) to efficiently compute digests for
messages with a common prefix.
}

@defproc[(digest-peek-final [dctx digest-ctx?])
         bytes?]{

Returns the digest without closing @racket[dctx], or @racket[#f] if
@racket[dctx] does not support copying.
}

@defproc[(make-hmac-ctx [di (or/c digest-spec? digest-impl?)]
                        [key bytes?])
         digest-ctx?]{

Like @racket[make-digest-ctx], but creates an HMAC context
parameterized over the digest @racket[di] and using the secret key
@racket[key].
}

@bibliography[
#:tag "digest-bibliography"

@bib-entry[#:key "HMAC"
           #:title "RFC 2104: HMAC: Keyed-Hashing for Message Authentication"
           #:url "http://www.ietf.org/rfc/rfc2104.txt"]

]

@(close-eval the-eval)
