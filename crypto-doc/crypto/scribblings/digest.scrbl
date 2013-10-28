#lang scribble/doc
@(require scribble/manual
          scribble/basic
          (for-label racket/base
                     racket/contract
                     crypto))

@title[#:tag "digest"]{Message Digests}

A @deftech{message digest} function (sometimes called a
@deftech{cryptographic hash} function) maps variable-length (and
potentially long) messages to fixed-length (and relatively short)
digests. For a good digest function, it is infeasible to find a
preimage of a given digest; that is, given an output, it is very hard
to find a corresponding input.

Different digest functions, or algorithms, compute digests of
different sizes and have different characteristics that may affect
their security. Examples of digest functions include SHA1, SHA256, and
SHA512. SHA1 computes an 160-bit (20-byte) digest; SHA256 computes a
256-bit digest; and SHA512 computes a 512-bit digest.

The HMAC (``Hash-based Message Authentication Code'') construction
combines a digest function together with a secret key. A Message
Authentication Code can be used in a security protocol to guarantee
message authentication and integrity.

This library provides both high-level, all-at-once digest operations
and low-level, incremental operations.

@section{Administrative Digest Functions}

@defproc[(digest-spec? [v any/c]) boolean?]{

Returns @racket[#f] if @racket[v] represents a @tech{digest
specification}, @racket[#f] otherwise.

A @deftech{digest specification} is a symbol, which is interpreted as
the name of a digest. Examples include @racket['sha1] and
@racket['sha512]. Another example is @racket['no-such-digest]---any
symbol is allowed; it is up to a specific cryptography provider to
determine whether it maps to a @tech{digest implementation}.

@;{FIXME: better to have known set of digests, then guarantee that
any spec maps to set of compatible impls???}

Future versions of this library may add other forms of digest
specifications.
}

@defproc[(digest-impl? [v any/c]) boolean?]{

Returns @racket[#f] if @racket[v] represents a @deftech{digest
implementation}, @racket[#f] otherwise.
}

@defproc[(digest-size [di (or/c digest-impl? digest-ctx?)])
         exact-positive-integer?]{

Returns the size in bytes of the digest computed by the algorithm
represented by @racket[di].
}

@defproc[(digest-block-size [d (or/c digest-impl? digest-ctx?)])
         exact-positive-integer?]{

Returns the size in bytes of the digest's internal block size. This
information is generally not needed by applications, but some
constructions (for example, HMAC) are defined in terms of a digest
function's block size.
}


@section{High-level Digest Functions}

@defproc[(digest [di digest-impl?]
                 [input (or/c bytes? string? input-port?)])
         bytes?]{

Computes the digest of @racket[input] using the digest function
represented by @racket[di].

If @racket[input] is a string, it is converted by bytes by calling
@racket[string->bytes/utf-8].  If @racket[input] is an input port, its
contents are read until until it produces @racket[eof], but the port
is not closed.
}

@defproc[(hmac [di digest-impl?]
               [key bytes?]
               [input (or/c bytes? string? input-port?)])
         bytes?]{

Like @racket[digest], but computes the HMAC of @racket[input]
parameterized by digest @racket[di] using the secret key
@racket[key]. The @racket[key] may be of any length, but the effective
security of the key is limited to @racket[(digest-block-size di)].
}


@section{Low-level Digest Functions}

@defproc[(make-digest-ctx [di digest-impl?])
         digest-ctx?]{

Creates a @deftech{digest context} for the digest function represented
by @racket[di]. A digest context can be incrementally updated with
message data.
}

@defproc[(digest-ctx?  [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is a @tech{digest context},
@racket[#f] otherwise.
}

@defproc[(digest-update [dctx digest-ctx?]
                        [input bytes?]
                        [start exact-nonnegative-integer? 0]
                        [end exact-nonnegative-integer? (bytes-length input)])
         void?]{

Updates @racket[dctx] with the message data corresponding to
@racket[(subbytes input start end)]. The @racket[digest-update]
function can be called multiple times, in which case @racket[dctx]
computes the digest of the concatenated inputs.
}

@defproc[(digest-final [dctx digest-ctx?])
         bytes?]{

Closes @racket[dctx] and returns the digest of the message.
}

@defproc[(digest-copy [dctx digest-ctx?])
         (or/c digest-ctx? #f)]{

Returns a copy of @racket[dctx], or @racket[#f] is the implementation
does not support copying. Use @racket[digest-copy] to efficiently
compute digests for messages with a common prefix.
}

@defproc[(digest-peek-final [dctx digest-ctx?])
         bytes?]{

Returns the digest without closing @racket[dctx], or @racket[#f] if
@racket[dctx] does not support copying.
}

@defproc[(make-hmac-ctx [di digest-impl?]
                        [key bytes?])
         digest-ctx?]{

Like @racket[make-digest-ctx], but creates an HMAC context
parameterized over the digest @racket[di] and using the secret key
@racket[key].
}

@defproc[(generate-hmac-key [di digest-impl?])
         bytes?]{

Generate a random secret key appropriate for HMAC parameterized over
digest @racket[di].
}
