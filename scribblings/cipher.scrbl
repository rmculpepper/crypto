#lang scribble/doc
@(require scribble/manual
          scribble/basic
          planet/scribble
          (for-label racket/base
                     racket/contract
                     (this-package-in main)))

@title[#:tag "cipher"]{Symmetric Ciphers}

@section{Cipher Algorithms}

A @scheme[<cipher>] is a first class object which captures cipher algorithm 
details.
The set of cipher algorithms depends on the local libcrypto configuration 
and is determined at module load-time.

@deftogether[(
@defthing[cipher:des <cipher>]
@defthing[cipher:des-ede <cipher>]
@defthing[cipher:des-ede3 <cipher>]
@defthing[cipher:idea <cipher>]
@defthing[cipher:bf <cipher>]
@defthing[cipher:cast5 <cipher>]
@defthing[cipher:aes-128 <cipher>]
@defthing[cipher:aes-192 <cipher>]
@defthing[cipher:aes-256 <cipher>]
@defthing[cipher:camellia-128 <cipher>]
@defthing[cipher:camellia-192 <cipher>]
@defthing[cipher:camellia-256 <cipher>]
)]{
Cipher algorithms. Bound to #f when an algorithm is unavailable.

The default mode of operation is cbc. Different modes are bound to
@scheme[<cipher>-mode], where mode is one of (ecb cbc cfb ofb).
}

@defproc[(available-ciphers) (list symbol?)]{
List of available cipher names.
}

@defproc[(!cipher? (o _)) boolean?]{
True if @scheme[o] is a @scheme[<cipher>].
}

@deftogether[(
@defproc[(cipher-block-size (o (or <cipher> cipher?))) 
         exact-nonnegative-integer?]
@defproc[(cipher-key-length (o (or <cipher> cipher?))) 
         exact-nonnegative-integer?]
@defproc[(cipher-iv-length (o (or <cipher> cipher?))) 
         exact-nonnegative-integer?]
)]{
Return the block size, key length, and iv length of @scheme[o]
}

@section{Encryption and Decryption}

@defproc*[(
[(encrypt (c <cipher>) (key bytes?) (iv bytes?))
 (values input-port? output-port?)]
[(encrypt (c <cipher>) (key bytes?) (iv bytes?) 
          (inp (or bytes? input-port?)))
 input-port?]
[(encrypt (c <cipher>) (key bytes?) (iv bytes?) 
          (inp (or bytes? input-port?))
          (outp (output-port?)))
 _]
)]{
Encrypt with cipher @scheme[c], using @scheme[key] as the secret key and
@scheme[iv] as the initialization vector.

The first form creates an encryption pipe.
The result is two values, an input-port where ciphertext can be
read from and an output-port where plaintext should be written to.

In the second form, when  @scheme[inp] is a port a half-pipe is created that
reads plaintext from @scheme[inp]; the result is a ciphertext input-port.
When @scheme[inp] is a byte string, then it is synchronously encrypted 
returning the ciphertext.

The third form synchronously encrypts plaintext from @scheme[inp], writing 
ciphertext to @scheme[outp].
}

@defproc*[(
[(decrypt (c <cipher>) (key bytes?) (iv bytes?))
 (values input-port? output-port?)]
[(decrypt (c <cipher>) (key bytes?) (iv bytes?) 
          (inp (or bytes? input-port?)))
 input-port?]
[(decrypt (c <cipher>) (key bytes?) (iv bytes?) 
          (inp (or bytes? input-port?))
          (outp (output-port?)))
 _]
)]{
Decrypt with cipher @scheme[c], using @scheme[key] as the secret key and
@scheme[iv] as the initialization vector.

Semantics of arguments and return values are symmetric to @scheme[encrypt].
}

@section{Low Level Cipher Operations}

Low level operations are performed on @emph{cipher contexts}.
The same set of operations is used both for encryption and decryption, 
depending on the initialization of the context.

@deftogether[(
@defproc[(cipher-encrypt (t <cipher>) (key bytes?) (iv bytes?) 
                         (#:padding pad? boolean? #t))
         cipher?]
@defproc[(cipher-decrypt (t <cipher>) (key bytes?) (iv bytes?) 
                         (#:padding pad? boolean? #t))
         cipher?]
)]{
Create and initialize a cipher context for encryption or decryption 
respectively.
}

@defproc*[(
[(cipher-update! (c cipher?) (ibs bytes?)) bytes?]
[(cipher-update! (c cipher?) (ibs bytes?) (obs bytes?))
 exact-nonnegative-integer?]
[(cipher-update! (c cipher?) (ibs bytes?) (obs bytes?)
                 (istart exact-nonnegative-integer?)
                 (iend exact-nonnegative-integer?)
                 (ostart exact-nonnegative-integer?)
                 (oend exact-nonnegative-integer?))
 exact-nonnegative-integer?]
)]{
Incrementally update a cipher context, with input @scheme[ibs].

The first form returns the output of the update; the other two forms 
write the output in @scheme[obs], which must have room for at least
@scheme[(cipher-block-length c)] plus the input length,  and return 
the number of bytes written.
}

@defproc*[(
[(cipher-final! (c cipher?)) bytes?]
[(cipher-final! (c cipher?) (obs bytes?)
                (ostart exact-nonnegative-integer? 0)
                (oend exact-nonnegative-integer? (bytes-length obs)))
 exact-nonnegative-integer?]
)]{
Finalize a cipher context.

The first form returns the final output block; the second form writes
the final output block in @scheme[obs], which must have room for at least 
@scheme[(cipher-block-size c)] bytes and return the number of bytes written.
}

@defproc[(cipher? (o _)) boolean?]{
True if @scheme[o] is a cipher context.
}

@defproc[(cipher-encrypt? (o cipher?)) boolean?]{
True if @scheme[o] is a cipher-context used for encryption.
}

