#lang scribble/doc
@(require scribble/manual
          scribble/basic
          scribble/eval
          (for-label racket/base
                     racket/contract
                     crypto
                     crypto/provider/libcrypto))

@(define the-eval (make-base-eval))
@(the-eval '(require crypto crypto/provider/libcrypto))

@title[#:tag "intro"]{Introduction to the Crypto Library}

Cryptography is not security.

Cryptography is a difficult, fragile tool that may be used in some
cases to achieve security goals.

This library is not a turn-key solution to security. It is a library
of low-level cryptographic operations---or, in other words, just
enough rope for the unwary to hang themselves.

This manual assumes that you already know to use cryptographic
operations properly. Every operation has conditions that must be
satisfied for the operation's security properties to hold. New
conditions are routinely discovered, and old conditions are not always
well-advertised in the appropriate documentation or literature. With a
few exceptions, such as the off-hand comment about CTR mode below,
@emph{this manual does not discuss them at all}. You are on your own.


@section[#:tag "intro-crypto"]{Cryptography Examples}

In order to use a cryptographic operation, you need an implementation
of it from a crypto provider. Implementations are managed through
crypto factories. This introduction will use the factory for libcrypto
(OpenSSL), since it is widely available and supports many useful
cryptographic operations. See @secref["factory"] for other crypto
providers.

@interaction[#:eval the-eval
(require crypto)
(require crypto/provider/libcrypto)
]

You can configure this library with a ``search path'' of crypto
factories:

@interaction[#:eval the-eval
(crypto-factories (list libcrypto-factory))
]

That allows you to perform an operation by providing a crypto
algorithm specifier, which is automatically resolved to an
implementation using the factories in @racket[(crypto-factories)]. For
example, to compute a message digest, call the @racket[digest]
function with the name of the digest algorithm:

@interaction[#:eval the-eval
(digest 'sha1 "Hello world!")
]

Or, if you prefer, you can obtain an algorithm implementation
explicitly:

@interaction[#:eval the-eval
(define sha1-impl (get-digest 'sha1 libcrypto-factory))
(digest sha1-impl "Hello world!")
]

To encrypt using a symmetric cipher, call the @racket[encrypt]
function with a cipher specifier consisting of the name of the cipher
and the cipher mode (see @racket[cipher-spec?] for details).

@interaction[#:eval the-eval
(define skey #"VeryVerySecr3t!!")
(define iv (make-bytes (cipher-iv-size '(aes ctr)) 0))
(encrypt '(aes ctr) skey iv "Hello world!")
]

Of course, using an all-zero IV is usually a very bad idea. (Using the
same key and IV to encrypt two plaintexts in CTR mode compromises both
plaintexts!) This library provides a function to generate a random IV
of the right size:

@interaction[#:eval the-eval
(define iv (generate-cipher-iv '(aes ctr)))
iv
]

There are also functions to generate session keys, HMAC keys, etc.

Randomness itself is a cryptographic operation, and crypto factories
also manage cryptographically-secure pseudo-random number generators
(CSPRNGs). The call to @racket[generate-cipher-iv] above used
@racket[(crypto-factories)] to find a CSPRNG. The following code uses
the libcrypto CSPRNG explicitly:

@interaction[#:eval the-eval
(define random-impl (get-random libcrypto-factory))
(random-bytes (cipher-iv-size '(aes ctr)) random-impl)
]

In addition to ``all-at-once'' operations like @racket[digest] and
@racket[encrypt], this library also supports algorithm contexts for
incremental computation.

@interaction[#:eval the-eval
(define sha1-ctx (make-digest-ctx 'sha1))
(digest-update sha1-ctx #"Hello ")
(digest-update sha1-ctx #"world!")
(digest-final sha1-ctx)
]

@section[#:tag "intro-pk"]{Public-Key Cryptography Examples}

