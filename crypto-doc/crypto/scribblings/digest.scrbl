#lang scribble/doc
@(require scribble/manual
          scribble/basic
          planet/scribble
          (for-label racket/base
                     racket/contract
                     (this-package-in main)))

@title[#:tag "digest"]{Message Digests}

@section{Digest Algorithms}

A @scheme[<digest>] is a first class object which captures algorithm details.
The set of digest algorithms depends on the local libcrypto configuration 
and is determined at module load-time.

@deftogether[(
@defthing[digest:md5 <digest>]
@defthing[digest:ripemd160 <digest>]
@defthing[digest:dss1 <digest>]
@defthing[digest:sha1 <digest>]
@defthing[digest:sha224 <digest>]
@defthing[digest:sha256 <digest>]
@defthing[digest:sha384 <digest>]
@defthing[digest:sha512 <digest>]
)]{
Digest algorithms. Bound to #f when an algorithm is unavailable.
}

@defproc[(available-digests) (list symbol?)]{
List of available digest names.
}

@defproc[(!digest? (o _)) boolean?]{
True if @scheme[o] is a @scheme[<digest>].
}

@defproc[(digest-size (o (or <digest> digest? hmac?))) 
         exact-nonnegative-integer?]{
The block size of a digest algorithm
}

@section{Computing Digests}

@defproc[(digest (t <digest>) (inp (or bytes? input-port?))) bytes?]{
Computes a digest for @scheme[inp] using @scheme[t] as the digest algorithm.
}

@deftogether[(
@defproc[(md5 (inp (or bytes? input-port?))) bytes?]
@defproc[(ripemd160 (inp (or bytes? input-port?))) bytes?]
@defproc[(dss1 (inp (or bytes? input-port?))) bytes?]
@defproc[(sha1 (inp (or bytes? input-port?))) bytes?]
@defproc[(sha224 (inp (or bytes? input-port?))) bytes?]
@defproc[(sha256 (inp (or bytes? input-port?))) bytes?]
@defproc[(sha384 (inp (or bytes? input-port?))) bytes?]
@defproc[(sha512 (inp (or bytes? input-port?))) bytes?]
)]{
Shortcuts for @scheme[(digest <digest> inp)].
}


@defproc[(hmac (t <digest>) (key bytes?) (inp (or bytes? input-port?))) bytes?]{
Computes an HMAC for @scheme[inp] using @scheme[t] as the digest algorithm
and @scheme[key] as the authentication key.
}

@section{Low Level Digest Operations}

Low level operations are performed on @emph{digest contexts} for message
digest computations and @emph{hmac contexts} for hmac computations.

@defproc[(digest-new (t <digest>)) digest?]{
Create and initialize a new digest context
}

@defproc[(digest-update! (o digest?) (data bytes?) 
                         (start exact-nonnegative-integer? 0)
                         (end exact-nonnegative-integer? (bytes-length data)))
         _]{
Incrementally update a digest context.
}

@defproc*[(
[(digest-final! (o digest?)) bytes?]
[(digest-final! (o digest?) (outp bytes?) 
                (start exact-nonnegative-integer? 0)
                (end exact-nonnegative-integer? (bytes-length outp)))
 exact-nonnegative-integer?]
)]{
Finalize the digest context.

The first form returns the output; The second form
writes the output in @scheme[outp] which must have enough room for the
digest and return the digest size.
}

@defproc[(digest-copy (o digest?)) digest?]{
Copies a digest context, which must not be finalized.
}

@defproc[(digest->bytes (o digest?)) bytes?]{
Returns the current value of the digest.
}

@defproc[(digest? (o _)) boolean?]{
True if @scheme[o] is a digest context.
}

@defproc[(hmac-new (t <digest>) (key bytes?)) hmac?]{
Create and initialize a hmac context
}

@defproc[(hmac-update! (o hmac?) (data bytes?) 
                       (start exact-nonnegative-integer? 0)
                       (end exact-nonnegative-integer? (bytes-length data)))
         _]{
Incrementally update an hmac context.
}

@defproc*[(
[(hmac-final! (o hmac?)) bytes?]
[(hmac-final! (o hmac?) (outp bytes?) 
              (start exact-nonnegative-integer? 0)
              (end exact-nonnegative-integer? (bytes-length outp)))
 exact-nonnegative-integer?]
)]{
Finalize an hmac context.
}

@defproc[(hmac? (o _)) boolean?]{
True if @scheme[o] is an hmac context.
}
