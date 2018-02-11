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

@(define-runtime-path log-file "eval-logs/cipher.rktd")
@(define the-eval (make-log-based-eval log-file 'replay))
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

The CCM block mode is not supported because of its burdensome
requirements: it requires the message and AAD lengths to be known in
advance.

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
(cipher-default-key-size '(chacha20 stream))
]
}

@defproc[(cipher-key-sizes [ci (or/c cipher-spec? cipher-impl?)])
         (listof exact-nonnegative-integer?)]{

Returns the possible sizes in bytes of the secret keys used by the
cipher.

@examples[#:eval the-eval
(cipher-key-sizes '(aes cbc))
(cipher-key-sizes '(chacha20 stream))
]
}

@defproc[(cipher-iv-size [ci (or/c cipher-spec? cipher-impl? cipher-ctx?)])
         exact-nonnegative-integer?]{

Returns the size in bytes of the @deftech{initialization vector} (IV)
used by the cipher. Returns @racket[0] if the cipher does not use an
IV.

This library uses a broad interpretation of the term ``IV''. For
example, if @racket[ci] is a block cipher in CTR mode, this function
returns the size of the counter.

@examples[#:eval the-eval
(cipher-iv-size '(aes cbc))
(cipher-iv-size '(aes ctr))
(cipher-iv-size '(aes gcm))
(cipher-iv-size '(aes ecb))
(cipher-iv-size '(chacha20-poly1305 stream))
(cipher-iv-size '(chacha20-poly1305/iv8 stream))
]
}

@defproc[(cipher-aead? [ci (or/c cipher-spec? cipher-impl? cipher-ctx?)]) boolean?]{

Returns @racket[#t] if @racket[ci] is an @tech{authenticated
encryption} cipher, @racket[#f] otherwise. See @racket[encrypt]
for more details.

An @deftech{authenticated encryption} cipher (with @emph{additionally
authenticated data}, AEAD) produces an @deftech{authentication tag} in
addition to the ciphertext. An AEAD cipher provides both
confidentiality and integrity, whereas a non-AEAD cipher only provides
confidentiality.

@examples[#:eval the-eval
(cipher-aead? '(aes ctr))
(cipher-aead? '(aes gcm))
(cipher-aead? '(chacha20-poly1305 stream))
]
}

@defproc[(cipher-default-auth-size [ci (or/c cipher-spec? cipher-impl? cipher-ctx?)])
         exact-nonnegative-integer?]{

Returns the default size in bytes of the @tech{authentication tag}
produced by @racket[ci] if it represents an @tech[#:key "authenticated
encryption"]{authenticated encryption or decryption} algorithm;
@racket[0] otherwise.

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
                  [input input/c]
                  [#:aad additional-authenticated-data input/c #""]
                  [#:auth-size auth-size exact-nonnegative-integer?
                               (cipher-default-auth-size ci)]
                  [#:pad pad-mode boolean? #t])
         bytes?]
@defproc[(decrypt [ci (or/c cipher-spec? cipher-impl?)]
                  [key bytes?]
                  [iv (or/c bytes? #f)]
                  [input (or/c bytes? input-port?)]
                  [#:aad additional-authenticated-data input/c #""]
                  [#:auth-size auth-size exact-nonnegative-integer?
                               (cipher-default-auth-size ci)]
                  [#:pad pad-mode boolean? #t])
         bytes?]
]]{

Encrypt or decrypt, respectively, using the secret @racket[key],
@tech{initialization vector} @racket[iv], and padding mode
@racket[pad-mode].  See @racket[input/c] for accepted values of
@racket[input] and @racket[additional-authenticated-data] and the
rules of their conversion to bytes.

If @racket[ci] is a block cipher and if @racket[pad-mode] is
@racket[#t], then the input is padded using PKCS#7 padding during
decryption, and the padding is checked and removed during decryption;
otherwise if @racket[pad-mode] is @racket[#f], then the input is not
padded, and its length must by divisible by @racket[ci]'s block
size. If @racket[ci] is a stream cipher (including block ciphers using
a stream mode), @racket[pad] is ignored and no padding is
added. Future versions of this library may support additional kinds of
padding.

If @racket[ci] is an @tech{authenticated encryption} (AEAD) cipher,
the @tech{authentication tag} it produces is @emph{attached} to the
ciphertext. That is, @racket[encrypt] appends the authentication tag
to the end of the ciphertext, and @racket[decrypt] extracts the
authentication tag from the end of the ciphertext. The
@racket[auth-size] argument controls the length of the authentication
tag. If authenticated decryption fails, an exception is raised.

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
                       [input input/c]
                       [#:aad additional-authenticated-data input/c #""]
                       [#:auth-size auth-size exact-nonnegative-integer?
                                    (cipher-default-auth-size ci)]
                       [#:pad pad-mode boolean? #t])
         (values bytes? bytes?)]
@defproc[(decrypt/auth [ci (or/c cipher-spec? cipher-impl?)]
                       [key bytes?]
                       [iv (or/c bytes? #f)]
                       [input (or/c bytes? input-port?)]
                       [#:aad additional-authenticated-data input/c #""]
                       [#:auth-tag auth-tag bytes? #""]
                       [#:pad pad-mode boolean? #t])
         bytes?]
]]{

Like @racket[encrypt] and @racket[decrypt], respectively, but the
authentication tag is @emph{detached} from the ciphertext. That is,
@racket[encrypt/auth] produces two values consisting of the ciphertext
and authentication tag, and @racket[decrypt/auth] takes the ciphertext
and authentication tag as distinct arguments.

If @racket[ci] is not an AEAD cipher, the authentication tag is always
@racket[#""].

@examples[#:eval the-eval
(define key (generate-cipher-key '(aes gcm)))
(define iv (generate-cipher-iv '(aes gcm)))
(define-values (ciphertext auth-tag)
  (encrypt/auth '(aes gcm) key iv "Hello world!" #:aad #"greeting"))
(decrypt/auth '(aes gcm) key iv ciphertext #:aad #"greeting" #:auth-tag auth-tag)
(decrypt/auth '(aes gcm) key iv ciphertext #:aad #"INVALID" #:auth-tag auth-tag)
]
}

@section{Low-level Cipher Operations}

@deftogether[[
@defproc[(make-encrypt-ctx [ci (or/c cipher-spec? cipher-impl?)]
                           [key bytes?]
                           [iv (or/c bytes? #f)]
                           [#:auth-size auth-size exact-nonnegative-integer?
                                        (cipher-default-auth-size ci)]
                           [#:auth-attached? auth-attached? boolean? #t]
                           [#:pad pad-mode boolean? #t])
         encrypt-ctx?]
@defproc[(make-decrypt-ctx [ci (or/c cipher-spec? cipher-impl?)]
                           [key bytes?]
                           [iv (or/c bytes? #f)]
                           [#:auth-size auth-size exact-nonnegative-integer?
                                        (cipher-default-auth-size ci)]
                           [#:auth-attached? auth-attached? boolean? #t]
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
                        [input input/c])
         bytes?]{

Processes @racket[input] with the cipher context @racket[cctx],
returning the newly available encrypted or decrypted output. The
output may be larger or smaller than the input, because incomplete
blocks are internally buffered by @racket[cctx].
}

@defproc[(cipher-update-aad [cctx cipher-ctx?]
                            [input input/c])
         void?]{

Processes @racket[input] as additional authenticated data to the
cipher context @racket[cctx]. Must be called before any calls to
@racket[cipher-update].

If @racket[cctx] is not a context for @tech[#:key "authenticated
encryption"]{authenticated encryption or decryption}, an exception is
raised.
}

@defproc[(cipher-final [cctx cipher-ctx?] [auth-tag (or/c bytes? #f)])
         bytes?]{

Processes any remaining input buffered by @racket[cctx], applies or
checks and removes padding if appropriate, and returns the newly
available output.

If @racket[cctx] is an @tech[#:key "authenticated encryption"]{
authenticated decryption} context in @emph{detached} mode (that is,
created with @racket[#:auth-attached? #f]), then @racket[auth-tag] is
checked against the decryption's final @tech{authentication tag} and
an exception is raised if they do not match.

Otherwise---if the @racket[cctx] is an encryption context, or a
decryption context for a non-AEAD cipher, or a decryption context for
an AEAD cipher in @emph{attached} mode---@racket[auth-tag] must be
@racket[#f] or else an exception is raised.
}

@defproc[(cipher-get-auth-tag [cctx cipher-ctx?])
         bytes?]{

If @racket[cctx] is an encryption context, retrieves the
authentication code. For a non-AEAD cipher, the authentication code is
always @racket[#""]. If called before @racket[cipher-final], an
exception is raised.
}

@(close-eval the-eval)
