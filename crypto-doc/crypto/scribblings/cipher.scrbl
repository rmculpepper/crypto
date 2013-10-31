#lang scribble/doc
@(require scribble/manual
          scribble/basic
          racket/list
          crypto/private/common/interfaces
          (for-label racket/base
                     racket/contract
                     crypto))

@title[#:tag "cipher"]{Ciphers: Symmetric Encryption}

A @deftech{cryptographic cipher} (or @deftech{symmetric-key encryption
algorithm}) is a reversable function from variable-length messages to
message. The input is called the ``plaintext'' and the output is
called the ``ciphertext''. For a good cipher, the ciphertext reveals
no information about the content of the plaintext (only its length or
approximate length); in particular, it is infeasible to compute the
plaintext corresponding to a given ciphertext without knowing the
secret key.

Ciphers are organized into families that share common encryption and
decryption algorithms but differ in parameters such as key length and
block mode. For example, the AES family supports key lengths of 128,
192, and 256 bits, and it supports a wide range of modes, including
ECB, CBC, and CTR.

This library provides both high-level, all-at-once encryption and
decryption operations and low-level, incremental operations.

@defproc[(cipher-spec? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] represents a @tech{cipher
specification}, @racket[#f] otherwise.

A @deftech{cipher specification} is one of the following:
@itemlist[

@item{@racket[(list 'stream _stream-cipher-symbol)]---where
@racket[_stream-cipher-symbol] is one of the following:
@(let ([stream-cipher-names (sort (hash-keys known-stream-ciphers) symbol<?)])
   (add-between (for/list ([name stream-cipher-names])
                  (racket '#,(racketvalfont (format "~a" name))))
                ", ")).}

@item{@racket[(list _block-mode _block-cipher-symbol)]---where 
@racket[_block-mode] is one of the following: 
@(add-between (for/list ([mode known-block-modes])
                (racket '#,(racketvalfont (format "~a" mode))))
              ", "),
and @racket[_block-cipher-symbol] is one of the following:
@(let ([block-cipher-names (sort (hash-keys known-block-ciphers) symbol<?)])
   (add-between (for/list ([name block-cipher-names])
                  (racket '#,(racketvalfont (format "~a" name))))
                ", ")).
Note that some modes, such as CTR, convert a block cipher
into a stream cipher.}
]

Future versions of this library may add other forms of cipher
specifications.
}

@defproc[(cipher-impl? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] represents a cipher implementation,
@racket[#f] otherwise.
}

@defproc[(cipher-block-size [c (or/c cipher-impl? cipher-ctx?)])
         exact-positive-integer?]{

Returns the size in bytes of the blocks manipulated by the cipher. If
@racket[c] is a stream cipher, returns @racket[1].

A cipher always produces a ciphertext that is a multiple of its block
size; depending on the cipher's padding mode, a plaintext must either
be a multiple of the block size, or it will automatically be padded to
a multiple of the block size.
}

@defproc[(cipher-key-size [c (or/c cipher-impl? cipher-ctx?)])
         exact-positive-integer?]{

Returns the size in bytes of the secret key accepted by the cipher.
}

@defproc[(cipher-iv-size [c (or/c cipher-impl? cipher-ctx?)])
         (or/c exact-positive-integer? #f)]{

Returns the size in bytes of the IV (initialization vector) accepted
by the cipher, or @racket[#f] if the cipher does not use an IV.
}

@section{High-level Cipher Operations}

@deftogether[[
@defproc[(encrypt [ci cipher-impl?]
                  [key bytes?]
                  [iv (or/c bytes? #f)]
                  [input (or/c bytes? string? input-port?)]
                  [#:pad pad-mode boolean? #t])
         bytes?]
@defproc[(decrypt [ci cipher-impl?]
                  [key bytes?]
                  [iv (or/c bytes? #f)]
                  [input (or/c bytes? string? input-port?)]
                  [#:pad pad-mode boolean? #t])
         bytes?]
]]{

Encrypt or decrypt, respectively, using the secret @racket[key],
initialization vector @racket[iv], and padding mode @racket[pad-mode].

If @racket[input] is a string, it is converted to bytes using
@racket[string->bytes/utf-8]. If @racket[input] is an input port, its
contents are read and processed unil an @racket[eof], but the port is
not closed.
}

@deftogether[[
@defproc[(encrypt-bytes [ci cipher-impl?]
                        [key bytes?]
                        [iv (or/c bytes? #f)]
                        [input bytes?]
                        [start exact-nonnegative-integer? 0]
                        [end exact-nonnegative-integer? (bytes-length input)]
                        [#:pad pad-mode boolean? #t])
         bytes?]
@defproc[(decrypt-bytes [ci cipher-impl?]
                        [key bytes?]
                        [iv (or/c bytes? #f)]
                        [input bytes?]
                        [start exact-nonnegative-integer? 0]
                        [end exact-nonnegative-integer? (bytes-length input)]
                        [#:pad pad-mode boolean? #t])
         bytes?]
]]{

Like @racket[encrypt] and @racket[decrypt], respectively, of
@racket[(subbytes input start end)].
}

@deftogether[[
@defproc[(encrypt-write [ci cipher-impl?]
                        [key bytes?]
                        [iv (or/c bytes? #f)]
                        [input (or/c bytes? string? input-port?)]
                        [out output-port?]
                        [#:pad pad-mode boolean? #t])
         exact-nonnegative-integer?]
@defproc[(decrypt-write [ci cipher-impl?]
                        [key bytes?]
                        [iv (or/c bytes? #f)]
                        [input (or/c bytes? string? input-port?)]
                        [out output-port?]
                        [#:pad pad-mode boolean? #t])
         exact-nonnegative-integer?]
]]{

Like @racket[encrypt] and @racket[decrypt], respectively, except that
the encrypted or decrypted output is written to @racket[out], and the
number of bytes written is returned.
}


@section{Low-level Cipher Operations}

@deftogether[[
@defproc[(make-encrypt-cipher-ctx [ci cipher-impl?]
                                  [key bytes?]
                                  [iv (or/c bytes? #f)]
                                  [#:pad pad-mode boolean? #t])
         cipher-ctx?]
@defproc[(make-decrypt-cipher-ctx [ci cipher-impl?]
                                  [key bytes?]
                                  [iv (or/c bytes? #f)]
                                  [#:pad pad-mode boolean? #t])
         cipher-ctx?]
]]{

Returns a new cipher context for encryption or decryption,
respectively, using the given secret @racket[key], initialization
vector @racket[iv], and padding mode @racket[pad-mode].

If @racket[pad-mode] is @racket[#t] and @racket[ci] is a block cipher,
then the input is padded using PKCS#7 padding: If @racket[_n] bytes of
padding are needed, then @racket[_n] copies of the byte @racket[_n]
are appended to the end of the input. If the input already ended at
the end of a block, an entire block of padding is added.  (PKCS#7
padding is the same as PKCS#5 padding, just defined for a wider range
of block sizes.)  If @racket[pad-mode] is @racket[#f], then the input
is not padded, and its length must by divisible by @racket[ci]'s block
size. If @racket[ci] is a stream cipher, no padding is added in either
case. Future versions of this library may support additional kinds of
padding.
}

@defproc[(cipher-ctx? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is a cipher context, @racket[#f]
otherwise.
}

@defproc[(cipher-encrypt? [cctx cipher-ctx?]) boolean?]{

Returns @racket[#t] if @racket[cctx] is a cipher context for
encryption (ie, created with @racket[make-encrypt-cipher-context]),
@racket[#f] otherwise.
}

@defproc[(cipher-update [cctx cipher-ctx?]
                        [input bytes?]
                        [start exact-nonnegative-integer? 0]
                        [end exact-nonnegative-integer? (bytes-length input)])
         bytes?]{

Processes @racket[(subbytes input start end)] with the cipher context
@racket[cctx], returning the newly available encrypted or decrypted
output. The output may be larger or smaller than the input, because
incomplete blocks are internally buffered by the cipher.
}

@defproc[(cipher-final [cctx cipher-ctx?])
         bytes?]{

Processes any remaining input buffered by @racket[cctx], applies
padding if appropriate, and returns the newly available output
}

@defproc[(generate-cipher-key+iv [ci cipher-impl?])
         (values bytes? (or/c bytes? #f))]{

Generates a random secret key and initialization vector appropriate
for use with the cipher @racket[ci].
}
