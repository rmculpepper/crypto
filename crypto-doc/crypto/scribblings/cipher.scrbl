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
@(add-between (for/list ([mode known-block-modes])
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

@defproc[(cipher-block-size [ci (or/c cipher-spec? cipher-impl? cipher-ctx?)])
         exact-positive-integer?]{

Returns the size in bytes of the blocks manipulated by the cipher. If
@racket[ci] is a stream cipher (including block ciphers using a stream
mode such as CTR), returns @racket[1].

A cipher produces a ciphertext that is a multiple of its block
size. If a cipher is used without padding, the plaintext must be a
multiple of the block size.

@examples[#:eval the-eval
(cipher-block-size '(aes cbc))
(cipher-block-size '(aes ctr))
(cipher-block-size '(salsa20 stream))
]
}

@defproc[(cipher-default-key-size [ci (or/c cipher-spec? cipher-impl?)])
         exact-nonnegative-integer?]{

Returns a default size in bytes of the secret keys used by the cipher.

@examples[#:eval the-eval
(cipher-default-key-size '(aes cbc))
(cipher-default-key-size '(blowfish cbc))
]
}

@defproc[(cipher-key-sizes [ci (or/c cipher-spec? cipher-impl?)])
         (listof exact-nonnegative-integer?)]{

Returns the possible sizes in bytes of the secret keys used by the
cipher.

@examples[#:eval the-eval
(cipher-key-sizes '(aes cbc))
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
(cipher-iv-size '(aes gcm))
(cipher-iv-size '(aes ecb))
(cipher-iv-size '(salsa20 stream))
]
}

@defproc[(cipher-aead? [ci (or/c cipher-spec? cipher-impl? cipher-ctx?)]) boolean?]{

Returns @racket[#t] if @racket[ci] is an @tech{authenticated
encryption} cipher, @racket[#f] otherwise. See @racket[encrypt/auth]
for more details.

@examples[#:eval the-eval
(cipher-aead? '(aes ctr))
(cipher-aead? '(aes gcm))
(cipher-aead? '(chacha20-poly1305 stream))
]
}

@defproc[(cipher-default-auth-size [ci (or/c cipher-spec? cipher-impl? cipher-ctx?)])
         (or/c exact-nonnegative-integer? #f)]{

Returns the default size in bytes of the @tech{authentication tag}
produced by @racket[ci] if it represents an @tech[#:key "authenticated
encryption"]{authenticated encryption or decryption} algorithm;
@racket[#f] otherwise.

@examples[#:eval the-eval
(cipher-default-auth-size '(aes gcm))
(cipher-default-auth-size '(aes ctr))
]
}

@deftogether[[
@defproc[(generate-cipher-key [ci (or/c cipher-spec? cipher-impl?)]
                              [#:size size exact-positive-integer? (cipher-default-key-size ci)])
         bytes?]
@defproc[(generate-cipher-iv [ci (or/c cipher-spec? cipher-impl?)]
                             [#:size size exact-positive-integer? (cipher-iv-size ci)])
         bytes?]
]]{

Generates a random secret key or initialization vector, respectively,
appropriate for use with the cipher @racket[ci]. Some ciphers have a
set of weak keys; @racket[generate-cipher-key] currently does
@emph{not} detect or avoid weak keys. If @racket[ci] does not use an
IV, @racket[generate-cipher-iv] returns @racket[#f].

The random bytes are generated with @racket[crypto-random-bytes].
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
                  [input (or/c bytes? input-port?)]
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
@defproc[(encrypt/auth [ci (or/c cipher-spec? cipher-impl?)]
                       [key bytes?]
                       [iv (or/c bytes? #f)]
                       [input (or/c bytes? string? input-port?)]
                       [#:pad pad-mode boolean? #t]
                       [#:AAD additional-auth-data (or/c bytes? #f) #f]
                       [#:auth-size auth-size (or/c exact-nonnegative-integer? #f)
                                    (cipher-default-auth-size ci)])
         (values bytes? (or/c bytes? #f))]
@defproc[(decrypt/auth [ci (or/c cipher-spec? cipher-impl?)]
                       [key bytes?]
                       [iv (or/c bytes? #f)]
                       [input (or/c bytes? input-port?)]
                       [#:pad pad-mode boolean? #t]
                       [#:AAD additional-auth-data (or/c bytes? #f) #f]
                       [#:auth-tag auth-tag bytes? #f])
         bytes?]
]]{

Like @racket[encrypt] and @racket[decrypt], respectively, except for
@deftech{authenticated encryption} modes such as GCM. The
@racket[encrypt/auth] function produces an @deftech{authentication
tag} of length @racket[auth-size] for the
@racket[additional-auth-data] and the @racket[input]. If
@racket[auth-size] is @racket[#f], the authentication tag is not
retrieved. The @racket[decrypt/auth] function raises an exception if
the given @racket[auth-tag] does not match the
@racket[additional-auth-data] and the @racket[input].

@examples[#:eval the-eval
(define key (generate-cipher-key '(aes gcm)))
(define iv (generate-cipher-iv '(aes gcm)))
(define-values (ciphertext auth-tag)
  (encrypt/auth '(aes gcm) key iv "Hello world!" #:AAD #"greeting"))
(decrypt/auth '(aes gcm) key iv ciphertext #:AAD #"greeting" #:auth-tag auth-tag)
(decrypt/auth '(aes gcm) key iv ciphertext #:AAD #"INVALID" #:auth-tag auth-tag)
]
}

@deftogether[[
@defproc[(encrypt-write [ci (or/c cipher-spec? cipher-impl?)]
                        [key bytes?]
                        [iv (or/c bytes? #f)]
                        [input (or/c bytes? string? input-port?)]
                        [out output-port? (current-output-port)]
                        [#:pad pad-mode boolean? #t])
         exact-nonnegative-integer?]
@defproc[(decrypt-write [ci (or/c cipher-spec? cipher-impl?)]
                        [key bytes?]
                        [iv (or/c bytes? #f)]
                        [input (or/c bytes? input-port?)]
                        [out output-port? (current-output-port)]
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
                           [#:pad pad-mode boolean? #t]
                           [#:auth-tag auth-tag (or/c bytes? #f) #f])
         decrypt-ctx?]
]]{

Returns a new cipher context for encryption or decryption,
respectively, using the given secret @racket[key], initialization
vector @racket[iv], and padding mode @racket[pad-mode].

The @racket[auth-tag] is used for
@tech[#:key "authenticated encryption"]{authenticated decryption}; 
see @racket[decrypt/auth].
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

@defproc[(cipher-update-AAD [cctx cipher-ctx?]
                            [input bytes?]
                            [start exact-nonnegative-integer? 0]
                            [end exact-nonnegative-integer? (bytes-length input)])
         void?]{

Processes @racket[(subbytes input start end)] as additional
authenticated data to the cipher context @racket[cctx]. Must be called
before any calls to @racket[cipher-update].

If @racket[cctx] is not a context for @tech[#:key "authenticated encryption"]{
authenticated encryption or decryption}, an exception is raised.
}

@defproc[(cipher-final [cctx cipher-ctx?])
         bytes?]{

Processes any remaining input buffered by @racket[cctx], applies or
checks and removes padding if appropriate, and returns the newly
available output.

If @racket[cctx] is an @tech[#:key "authenticated encryption"]{
authenticated decryption} context, then the function
raises an exception if the @tech{authentication tag} does not match. See also
@racket[decrypt/auth].

If @racket[cctx] is an @tech{authenticated encryption} context, use
@racket[cipher-final/tag] instead.
}

@defproc[(cipher-final/tag [cctx encrypt-ctx?]
                           [#:auth-size auth-size exact-nonnegative-integer?
                                        (cipher-default-auth-size cctx)])
         (values bytes? bytes?)]{

Like @racket[cipher-final], but also return an @tech{authentication tag}. The
@racket[cctx] argument must be an @tech{authenticated encryption}
context. See also @racket[encrypt/auth].
}

@(close-eval the-eval)
