#lang scribble/doc
@(require scribble/manual
          scribble/basic
          racket/list
          crypto/private/common/catalog
          (for-label racket/base
                     racket/contract
                     crypto))

@title[#:tag "digest"]{Message Digests}

A message digest function (sometimes called a cryptographic hash
function) maps variable-length (and potentially long) messages to
fixed-length (and relatively short) digests. @;{For a good digest
function, it is infeasible to find a preimage of a given digest; that
is, given an output, it is very hard to find a corresponding input.}
Different digest functions, or algorithms, compute digests of
different sizes and have different characteristics that may affect
their security.

@emph{Take care when choosing a digest for new development.}  Several
of the digests listed available through this library are now
considered insecure or broken. At the time of this writing (October
2013), the safest choices are probably the SHA2 family
(@racket['sha224], @racket['sha256], @racket['sha384], and
@racket['sha512]).

The HMAC (``Hash-based Message Authentication Code'') construction
combines a digest function together with a secret key. A Message
Authentication Code can be used in a security protocol to guarantee
message authentication and integrity.

This library provides both high-level, all-at-once digest operations
and low-level, incremental operations.

@section{Administrative Digest Functions}

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
}

@defproc[(digest-block-size [di (or/c digest-spec? digest-impl? digest-ctx?)])
         exact-positive-integer?]{

Returns the size in bytes of the digest's internal block size. This
information is usually not needed by applications, but some
constructions (such as HMAC) are defined in terms of a digest
function's block size.
}

@defproc[(generate-hmac-key [di (or/c digest-spec? digest-impl?)])
         bytes?]{

Generate a random secret key appropriate for HMAC parameterized over
digest @racket[di]. The length of the key is @racket[(digest-size di)].
}


@section{High-level Digest Functions}

@defproc[(digest [di (or/c digest-spec? digest-impl?)]
                 [input (or/c bytes? string? input-port?)])
         bytes?]{

Computes the digest of @racket[input] using the digest function
represented by @racket[di].

If @racket[input] is a string, it is converted by bytes by calling
@racket[string->bytes/utf-8].  If @racket[input] is an input port, its
contents are read until until it produces @racket[eof], but the port
is not closed.
}

@defproc[(hmac [di (or/c digest-spec? digest-impl?)]
               [key bytes?]
               [input (or/c bytes? string? input-port?)])
         bytes?]{

Like @racket[digest], but computes the HMAC of @racket[input]
parameterized by digest @racket[di] using the secret key
@racket[key]. The @racket[key] may be of any length, but the effective
security of the key is limited to @racket[(digest-block-size di)]; a
common key-length is @racket[(digest-size di)] @cite{HMAC}.
}

@section{Low-level Digest Functions}

@defproc[(make-digest-ctx [di (or/c digest-spec? digest-impl?)])
         digest-ctx?]{

Creates a digest context for the digest function represented by
@racket[di]. A digest context can be incrementally updated with
message data.
}

@defproc[(digest-ctx? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is a digest context, @racket[#f]
otherwise.
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
