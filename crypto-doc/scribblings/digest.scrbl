#lang scribble/doc
@(require scribble/manual
          scribble/basic
          scribble/eval
          racket/list
          racket/class
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

@title[#:tag "digest"]{Message Digests and Authentication Codes}

A @as-index{message digest function} (sometimes called a @as-index{cryptographic
hash function}) maps a variable-length, potentially long message to a relatively
short digest. Different digest functions, or algorithms, compute digests of
different sizes and have different characteristics that may affect their
security. Message digest functions may be divided into three groups according to
their output size: @itemlist[

@item{A fixed-length digest function always produces the same size
output. Examples include SHA1 (20 bytes) and SHA512 (64 bytes).}

@item{A variable-length digest function is parameterized by the output
length. The output length must be committed to before a message can begin to be
processed. Given the same message, a variable-length digest function produces
unrelated outputs for different lengths. An example is BLAKE2B.}

@item{An @as-index{extendable output function} (XOF) is like a variable-length
digest function, except the output size may be selected after the message is
fully processed. Given the same message and two different output lengths, an XOF
always produces outputs where the shorter output is a prefix of the longer
output. An example is SHAKE128.}

]
Some message digest functions are parameterized by a secret key. Such a digest
is called a @as-index{message authentication code} (MAC). This library supports
MACs using the same API as other digests. Examples include BLAKE2B and the HMAC
construction @cite{HMAC}.

This library provides both high-level, all-at-once digest operations
and low-level, incremental operations.

@(begin
   (define (rktquote s) @racket[(quote @#,(racketvalfont (format "~a" s)))])
   (define (get-size di) (send di get-size*))
   (define (size< a b)
     (cond [(and (real? a) (real? b)) (< a b)]
           [(real? b) #f] [(real? a) #t]
           [else (symbol<? a b)]))
   (define (get-sort-string di)
     (define str (format "~a" (send di get-spec)))
     (string-append (cond [(regexp-match? #rx"^sha3-" str) "3"]
                          [(regexp-match? #rx"^sha[0-9]" str) "1"]
                          [else "9"])
                    str)))

@defproc[(digest-spec? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] represents a digest specifier, @racket[#f]
otherwise.

A digest specifier is a symbol, which is interpreted as the name of a
digest. The following table lists valid digest names:
@tabular[
#:sep @hspace[2]
#:column-properties '(left right)
(cons
 (list @bold{Digests} @bold{Size})
 (let ()
   (define all-infos (sort (hash-values known-digests) size< #:key get-size))
   (define by-size (group-by get-size all-infos))
   (for/list ([group (in-list by-size)])
     (list @elem[(add-between (for/list ([di (in-list (sort group string<? #:key get-sort-string))])
                                (rktquote (send di get-spec)))
                              ", ")]
           @(let ([size (send (car group) get-size*)])
              (case size
                [(xof) @elem{XOF}]
                [(var) @elem{variable}]
                [else @elem[(format "~a" size)]]))))))
]
Not every digest name above necessarily has an available implementation,
depending on the cryptography providers installed.

Future versions of this library may add other forms of digest
specifiers.
}

@defproc[(digest-impl? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] represents a digest implementation,
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
         (or/c exact-positive-integer? #f)]{

Returns the size in bytes of the digest computed by the algorithm represented by
@racket[di]. If @racket[di] is an XOF, @racket[#f] is returned.

@examples[#:eval the-eval
(digest-size 'sha1)
(digest-size 'sha256)
(digest-size 'shake128)
]

@history[#:changed "2.1" @elem{Added @racket[#f] result value for XOFs.}]}

@defproc[(digest-xof? [di (or/c digest-spec? digest-impl? digest-ctx?)])
         boolean?]{

Returns @racket[#t] is @racket[di] is an XOF (Extendable Output Function),
@racket[#f] otherwise. Equivalent to @racket[(not (digest-size di))].

@history[#:added "2.1"]
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

@defproc[(digest-security-strength [di (or/c digest-spec? digest-impl? digest-ctx?)]
                                   [cr? boolean?])
         (or/c #f security-strength/c)]{

Returns the @tech{security strength} rating of the digest algorithm
represented by @racket[di], or @racket[#f] if the rating is
unknown. The result may be @racket[0] for algorithms considered
insecure.

If @racket[cr?] is true, the result reflects @racket[di]'s strength in
contexts requiring collision resistance (such as digital signatures);
if @racket[cr?] is false, the result reflects @racket[di]'s strength
assuming collision resistance is not required (such as with HMAC).

@examples[#:eval the-eval
(digest-security-strength 'sha1 #t)
(digest-security-strength 'sha1 #f)
(digest-security-strength 'sha384 #t)
]

@history[#:added "1.8"]}

@defproc[(generate-hmac-key [di (or/c digest-spec? digest-impl?)])
         bytes?]{

Generate a random secret key appropriate for HMAC using digest @racket[di]. The
length of the key is @racket[(digest-size di)]; @racket[di] must not be an XOF.
The random bytes are generated with @racket[crypto-random-bytes].
}


@section{High-level Digest Functions}

@defproc[(digest [di (or/c digest-spec? digest-impl?)]
                 [input input/c]
                 [#:key key (or/c bytes? #f) #f]
                 [#:size size (or/c exact-positive-integer? #f) #f])
         bytes?]{

Computes the digest of @racket[input] using the digest function
represented by @racket[di]. See @racket[input/c] for accepted values
and their conversions to bytes.

If @racket[di] supports keys (eg, the BLAKE2 family of digests), then
@racket[key] is used as the digest key if it is a byte string; if @racket[key]
is @racket[#f], the digest is used in unkeyed mode. If @racket[di] does not
support keys, then @racket[key] must be @racket[#f] or else an error is raised.

If @racket[di] is an XOF, then @racket[size] must be an integer, and the
resulting byte string has @racket[size] bytes. If @racket[di] is not an XOF,
then @racket[size] must be @racket[#f] or @racket[(digest-size di)].

@examples[#:eval the-eval
(digest 'sha1 "Hello world!")
(digest 'sha256 "Hello world!")
(digest 'shake128 "Hello world!" #:size 57)
]

@history[#:changed "2.1" @elem{Added @racket[#:size] argument to support XOFs.}]
}

@defproc[(hmac [di (or/c digest-spec? digest-impl?)]
               [key bytes?]
               [input input/c])
         bytes?]{

Like @racket[digest], but computes the HMAC of @racket[input] using
digest @racket[di] and the secret key @racket[key]. The @racket[key]
may be of any length, but @racket[(digest-size di)] is a typical
key length @cite{HMAC}.

The digest @racket[di] must not be an XOF.
}

@section{Low-level Digest Functions}

@defproc[(make-digest-ctx [di (or/c digest-spec? digest-impl?)]
                          [#:key key (or/c bytes? #f) #f])
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

@defproc[(digest-final [dctx digest-ctx?]
                       [#:size size (or/c exact-positive-integer? #f) #f])
         bytes?]{

Returns the digest of the message accumulated in @racket[dctx] so far
and closes @racket[dctx]. Once @racket[dctx] is closed, any further
operation performed on it will raise an exception.

If @racket[dctx] belongs to an XOF, then size must be an integer, and the
resulting byte string has @racket[size] bytes; otherwise, @racket[size] must be
@racket[#f] or @racket[(digest-size dctx)].

@history[#:changed "2.1" @elem{Added @racket[#:size] argument to support XOFs.}]
}

@defproc[(digest-copy [dctx digest-ctx?])
         (or/c digest-ctx? #f)]{

Returns a copy of @racket[dctx], or @racket[#f] is the implementation
does not support copying. Use @racket[digest-copy] (or
@racket[digest-peek-final]) to efficiently compute digests for
messages with a common prefix.
}

@defproc[(digest-peek-final [dctx digest-ctx?]
                            [#:size size (or/c exact-positive-integer? #f) #f])
         bytes?]{

Returns the digest without closing @racket[dctx], or @racket[#f] if
@racket[dctx] does not support copying.

@history[#:changed "2.1" @elem{Added @racket[#:size] argument to support XOFs.}]
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
