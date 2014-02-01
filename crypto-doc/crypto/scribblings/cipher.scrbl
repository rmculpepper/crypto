#lang scribble/doc
@(require scribble/manual
          scribble/basic
          scribble/eval
          racket/list
          crypto/private/common/catalog
          (for-label racket/base
                     racket/contract
                     crypto))

@(define the-eval (make-base-eval))
@(the-eval '(require crypto crypto/provider/libcrypto))
@(the-eval '(crypto-factories (list libcrypto-factory)))

@title[#:tag "cipher"]{Symmetric Encryption}

A cipher (or symmetric-key encryption algorithm) is a reversable
function from variable-length messages to messages. The input is
called the ``plaintext'' and the output is called the ``ciphertext.''
For a good cipher, the ciphertext reveals no information about the
contents of the plaintext (only its length or approximate length); in
particular, it is infeasible to compute the plaintext corresponding to
a given ciphertext without knowing the secret key.

Ciphers are organized into families that share common encryption and
decryption algorithms but differ in parameters such as key length and
block mode. For example, the AES family supports key lengths of 128,
192, and 256 bits, and it supports a wide range of modes, including
ECB, CBC, and CTR.

This library provides both high-level, all-at-once encryption and
decryption operations and low-level, incremental operations.

@defproc[(cipher-spec? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] represents a cipher specifier,
@racket[#f] otherwise.

A cipher specifier is one of the following:
@itemlist[

@item{@racket[(list _stream-cipher 'stream)]---where
@racket[_stream-cipher] is one of the following symbols:
@(let ([stream-cipher-names (sort (hash-keys known-stream-ciphers) symbol<?)])
   (add-between (for/list ([name stream-cipher-names])
                  (racket '#,(racketvalfont (format "~a" name))))
                ", ")).}

@item{@racket[(list _block-cipher _block-mode)]---where 
@racket[_block-cipher] is one of the following symbols:
@(let ([block-cipher-names (sort (hash-keys known-block-ciphers) symbol<?)])
   (add-between (for/list ([name block-cipher-names])
                  (racket '#,(racketvalfont (format "~a" name))))
                ", ")),
and @racket[_block-mode] is one of the following symbols: 
@(add-between (for/list ([mode (map car known-block-modes)])
                (racket '#,(racketvalfont (format "~a" mode))))
              ", ").}
]

Note that the key length is not considered part of the cipher
specifier; it is determined implicitly from the key provided to
@racket[encrypt], @racket[make-encrypt-ctx], etc.

Future versions of this library may add more ciphers to the lists
above and other forms of cipher specifiers.
}

@defproc[(cipher-impl? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] represents a cipher implementation,
@racket[#f] otherwise.
}


@defproc[(get-cipher [ci cipher-spec?]
                     [factories (or/c crypto-factory? (listof crypto-factory?))
                                (crypto-factories)])
         (or/c cipher-impl? #f)]{

Returns an implementation of cipher @racket[ci] from the given
@racket[factories]. If no factory in @racket[factories] implements
@racket[ci], returns @racket[#f].
}

@defproc[(cipher-default-key-size [ci (or/c cipher-spec? cipher-impl?)])
         exact-nonnegative-integer?]{

Returns the default size in bytes of the secret keys used by the cipher.

@examples[#:eval the-eval
(cipher-default-key-size '(aes cbc))
(cipher-default-key-size '(blowfish cbc))
]
}

@defproc[(cipher-key-sizes [ci (or/c cipher-spec? cipher-impl?)])
         (or/c (listof exact-nonnegative-integer?) variable-size?)]{

Returns the possible sizes in bytes of the secret keys used by the
cipher.

@examples[#:eval the-eval
(cipher-key-sizes '(aes cbc))
(cipher-key-sizes '(blowfish cbc))
]
}

@defproc[(cipher-block-size [ci (or/c cipher-spec? cipher-impl? cipher-ctx?)])
         exact-positive-integer?]{

Returns the size in bytes of the blocks manipulated by the cipher. If
@racket[ci] is a stream cipher (including block ciphers using a stream
mode such as CTR), returns @racket[1].

A cipher always produces a ciphertext that is a multiple of its block
size. If a cipher is used without padding, the plaintext must be a
multiple of the block size.

@examples[#:eval the-eval
(cipher-block-size '(aes cbc))
(cipher-block-size '(aes ctr))
(cipher-block-size '(salsa20 stream))
]
}

@defproc[(cipher-iv-size [ci (or/c cipher-spec? cipher-impl? cipher-ctx?)])
         exact-nonnegative-integer?]{

Returns the size in bytes of the IV (initialization vector) used by
the cipher. Returns @racket[0] if the cipher does not use an IV.

This library uses a broad interpretation of the term ``IV''; for
example, if @racket[ci] is a block cipher in CTR mode, this function
returns the size of the counter.

@examples[#:eval the-eval
(cipher-iv-size '(aes cbc))
(cipher-iv-size '(aes ctr))
(cipher-iv-size '(aes ecb))
(cipher-iv-size '(salsa20 stream))
]
}

@defproc[(generate-cipher-key [ci (or/c cipher-spec? cipher-impl?)])
         bytes?]{

Generates a random secret key appropriate for use with the cipher
@racket[ci]. Note: some ciphers have a set of weak keys;
@racket[generate-cipher-key] currently does not detect or avoid weak
keys.
}

@defproc[(generate-cipher-iv [ci (or/c cipher-spec? cipher-impl?)])
         (or/c bytes? #f)]{

Generates a random initialization vector appropriate for use with the
cipher @racket[ci]. If @racket[ci] does not use an IV, returns
@racket[#f].
}


@section{High-level Cipher Operations}

@deftogether[[
@defproc[(encrypt [ci (or/c cipher-spec? cipher-impl?)]
                  [key bytes?]
                  [iv (or/c bytes? #f)]
                  [input (or/c bytes? string? input-port?)]
                  [#:pad pad-mode boolean? #t])
         bytes?]
@defproc[(decrypt [ci (or/c cipher-spec? cipher-impl?)]
                  [key bytes?]
                  [iv (or/c bytes? #f)]
                  [input (or/c bytes? string? input-port?)]
                  [#:pad pad-mode boolean? #t])
         bytes?]
]]{

Encrypt or decrypt, respectively, using the secret @racket[key],
initialization vector @racket[iv], and padding mode @racket[pad-mode].
This @racket[iv] argument is the IV for CBC mode, the initial counter
for CTR mode, etc.

If @racket[input] is a string, it is converted to bytes using
@racket[string->bytes/utf-8]. If @racket[input] is an input port, its
contents are read and processed unil an @racket[eof], but the port is
not closed.

If @racket[pad-mode] is @racket[#t] and @racket[ci] is a block cipher,
then the input is padded using PKCS#7 padding during decryption, and
the padding is checked and removed during decryption. If @racket[_n]
bytes of padding are needed, then @racket[_n] copies of the byte
@racket[_n] are appended to the end of the input. If the input already
ended at the end of a block, an entire block of padding is added.  If
@racket[pad-mode] is @racket[#f], then the input is not padded, and
its length must by divisible by @racket[ci]'s block size. If
@racket[ci] is a stream cipher (including block ciphers using a stream
mode), no padding is added in either case. Future versions of this
library may support additional kinds of padding.

@examples[#:eval the-eval
(define key (generate-cipher-key '(aes ctr)))
(define iv (generate-cipher-iv '(aes ctr)))
(define ciphertext (encrypt '(aes ctr) key iv "Hello world!"))
ciphertext
(decrypt '(aes ctr) key iv ciphertext)
]
}

@deftogether[[
@defproc[(encrypt-write [ci (or/c cipher-spec? cipher-impl?)]
                        [key bytes?]
                        [iv (or/c bytes? #f)]
                        [input (or/c bytes? string? input-port?)]
                        [out output-port?]
                        [#:pad pad-mode boolean? #t])
         exact-nonnegative-integer?]
@defproc[(decrypt-write [ci (or/c cipher-spec? cipher-impl?)]
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
@defproc[(make-encrypt-ctx [ci (or/c cipher-spec? cipher-impl?)]
                           [key bytes?]
                           [iv (or/c bytes? #f)]
                           [#:pad pad-mode boolean? #t])
         encrypt-ctx?]
@defproc[(make-decrypt-ctx [ci (or/c cipher-spec? cipher-impl?)]
                           [key bytes?]
                           [iv (or/c bytes? #f)]
                           [#:pad pad-mode boolean? #t])
         decrypt-ctx?]
]]{

Returns a new cipher context for encryption or decryption,
respectively, using the given secret @racket[key], initialization
vector @racket[iv], and padding mode @racket[pad-mode].
}

@defproc[(cipher-ctx? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is a cipher context, @racket[#f]
otherwise. 

Equivalent to @racket[(or (encrypt-ctx? v) (decrypt-ctx? v))].
}

@deftogether[[
@defproc[(encrypt-ctx? [v any/c]) boolean?]
@defproc[(decrypt-ctx? [v any/c]) boolean?]
]]{

Returns @racket[#t] if @racket[v] is a cipher context for encryption
or decryption, respectively; otherwise, returns @racket[#f].
}

@defproc[(cipher-update [cctx cipher-ctx?]
                        [input bytes?]
                        [start exact-nonnegative-integer? 0]
                        [end exact-nonnegative-integer? (bytes-length input)])
         bytes?]{

Processes @racket[(subbytes input start end)] with the cipher context
@racket[cctx], returning the newly available encrypted or decrypted
output. The output may be larger or smaller than the input, because
incomplete blocks are internally buffered by @racket[cctx].
}

@defproc[(cipher-final [cctx cipher-ctx?])
         bytes?]{

Processes any remaining input buffered by @racket[cctx], applies or
checks and removes padding if appropriate, and returns the newly
available output.
}


@(close-eval the-eval)
