#lang scribble/doc
@(require 
  scribble/manual
  scribble/basic
  ;;(for-label "main.ss" "util.ss" scheme) ; fucking piece of shit scribble
  (for-label scheme)
  )

@title{mzcrypto}

@section{Overview}

mzcrypto is a cryptographic library for mzscheme.

The library provides a high level interface for accessing primitives
from libcrypto.
To use this library you will need OpenSSL (0.9.8 or later) installed on 
your system.

@subsection{Installation}

To use the library  through PLaneT:
@schemeinput[
(require (planet vyzo/crypto))
]

To locally install the library, extract the library archive to your 
collects directory and run
@commandline{setup-plt -l crypto}

To use the local library:
@schemeinput[
(require crypto)
]

To run basic tests on the library:
@schemeinput[(require (planet vyzo/crypto/test))]
or if you have locally installed:
@schemeinput[(require crypto/test)]

@schemeinput[(run-tests)]

@subsection{License}

(C) Copyright 2007-2009 Dimitris Vyzovitis <vyzo at media.mit.edu>
 
mzcrypto is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
mzcrypto is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.
 
You should have received a copy of the GNU Lesser General Public License
 along with mzcrypto.  If not, see 
@link["http://www.gnu.org/licenses/"]{<http://www.gnu.org/licenses/>}.

@section{API Organization}

@defmodule*/no-declare[(crypto (planet vyzo/crypto))]

The API provided by mzcrypto is conceptually organized in 5 sections:
@itemize{
@item{@secref{digest}}
@item{@secref{cipher}}
@item{@secref{pkey}}
@item{@secref{dh}}
@item{@secref{util}}
}

Each section documents the relevant scheme bindings, with 
tutorial-style examples  in @secref{examples}

@section[#:tag "digest"]{Message Digests}
@declare-exporting{digest.ss}

@subsection{Digest Algorithms}


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

@subsection{Computing Digests}

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

@subsection{Low Level Digest Operations}

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

@section[#:tag "cipher"]{Symmetric Ciphers}
@declare-exporting{cipher.ss}

@subsection{Cipher Algorithms}

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

@subsection{Encryption and Decryption}

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

@subsection{Low Level Cipher Operations}

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


@section[#:tag "pkey"]{Public Key Cryptography}
@declare-exporting{pkey.ss}

@subsection{Algorithms and Keys}

A @scheme[<pkey>] is a first class object which captures public key algorithm 
details. Key-pairs can be generated using @scheme[generate-key] with a 
@scheme[<pkey>].

@deftogether[(
@defthing[pkey:rsa <pkey>]
@defthing[pkey:dsa <pkey>]
)]{
Builtin @scheme[<pkey>] algorithms.
}

@defproc[(!pkey? (o _)) boolean?]{
True if @scheme[o] is a @scheme[<pkey>].
}

@defproc[(pkey? (o _)) boolean?]{
True if @scheme[o] is a public or private key.
}

@defproc[(pkey-private? (o pkey?)) boolean?]{
True if @scheme[o] is a private key.
}

@defproc[(pkey->public-key (o pkey?)) pkey?]{
Extracts the public key component.
}

@deftogether[(
@defproc[(public-key->bytes (o pkey?)) bytes?]
@defproc[(private-key->bytes  (o pkey?)) bytes?]
@defproc[(bytes->public-key (bs bytes?)) pkey?]
@defproc[(bytes->private-key (bs bytes?)) pkey?]
)]{
Conversions between keys and bytes.
}

@deftogether[(
@defproc[(pkey-size (o pkey?)) exact-nonnegative-integer?]
@defproc[(pkey-bits (o pkey?)) exact-nonnegative-integer?]
)]{
The size of a key in bytes and bits respectively.
}

@defproc[(pkey=? (x pkey?) ...+) boolean?]{
Key equality predicate.
}

@subsection{Signatures}

@defproc[(sign (pk pkey?) (t <digest>) (data (or bytes? input-port?)))
          bytes?]{
Computes a signature, using the @emph{private} key @scheme[pk] and @scheme[t]
as the digest type.

@bold{Note}: As of openssl-0.9.8 only certain types of digests can be used
with specific public key algorithms. Specifically, @scheme[pkey:rsa] keys
can only sign using @scheme[sha*] and @scheme[ripemd160] as digests, 
while @scheme[pkey:dsa] can only sign with @scheme[dss1] digests.

This restriction has been removed in development versions of openssl (0.9.9).
}

@defproc[(verify (pk pkey?) (t <digest>) (sig bytes?) (data (or bytes? input-port?)))
         boolean?]{
Verifies a signature @scheme[sig], using the @emph{public} key @scheme[pk] and
@scheme[t] as the digest type.
}

@deftogether[(
@defproc*[(
[(digest-sign (dg digest?) (pk pkey?)) bytes?]
[(digest-sign (dg digest?) (pk pkey?) (bs bytes?) 
              (start exact-nonnegative-integer? 0)
              (end exact-nonnegative-integer? (bytes-length bs)))
 exact-nonnegative-integer?]
)]
@defproc[(digest-verify (dg digest?) (pk pkey?) (bs bytes?)
                        (start exact-nonnegative-integer? 0)
                        (end exact-nonnegative-integer? (bytes-length bs)))
          boolean?]
)]{
Signature and verification using digest contexts directly.
}

@subsection{Encryption}

@deftogether[(
@defproc[(encrypt/pkey (pk pkey?) (data bytes?)
                       (start exact-nonnegative-integer? 0)
                       (end exact-nonnegative-integer? (bytes-length data)))
          bytes?]
@defproc[(decrypt/pkey (pk pkey?) (data bytes?)
                       (start exact-nonnegative-integer? 0)
                       (end exact-nonnegative-integer? (bytes-length data)))
          bytes?]
)]{
Encrypt and decrypt using a public/private key.
}

@defproc[(encrypt/envelope (pk pkey?) (c <cipher>) (arg _) ...)
         (values bytes? bytes? _ ...)]{
Encrypt using @scheme[c] as the @scheme[<cipher>] with a random key
sealed using the @emph{public} key @scheme[pkey].

Returns the sealed key and iv for the cipher, prepended to the values
returned by the nested @scheme[encrypt].
}

@defproc[(decrypt/envelope (pk pkey?) (c <cipher>) (sk bytes?) (iv bytes?)
          (arg _) ...)
         (values _ ...)]{
Decrypt using @scheme[c] as the @scheme[<cipher>], using the 
sealed key @scheme[sk] decrypted with the @emph{private} key @scheme[pk].
}

@section[#:tag "dh"]{Diffie-Hellman Key Exchange}
@declare-exporting{dh.ss}

Diffie-Hellman key parameters are encapsulated in instances of @scheme[<dh>].
Keys can be generated from a parameter instance using @scheme[generate-key].

@deftogether[(
@defthing[dh:192 <dh>]
@defthing[dh:512 <dh>]
@defthing[dh:1024 <dh>]
@defthing[dh:2048 <dh>]
@defthing[dh:4096 <dh>]
)]{
Pre-computed Diffie-Hellman parameters from the OpenSSL project.
}

@defproc[(compute-key (priv dhkey?) (key bytes?)) bytes?]{
Computes a shared key using the private key @scheme[priv] and the peer 
public key @scheme[key].
}

@defproc[(dhkey? (o _)) boolean?]{
True if @scheme[o] is a Diffie-Hellman key.
}

@defproc[(!dh? (o _)) boolean?]{
True if @scheme[o] is a @scheme[<dh>] parameter object.
}

@defproc[(dh-bits (o <dh>)) exact-nonnegative-integer?]{
The size in bits of the keys generated from @scheme[o].
}

@section[#:tag "util"]{Utilities}

@subsection{Key Generation}
@declare-exporting["keygen.ss"]

@defproc*[(
[(generate-key (t <cipher>)) (values bytes? bytes?)]
[(generate-key (t <pkey>) (bits exact-nonnegative-integer?) (arg _) ...) 
         pkey?]
[(generate-key (t <digest>)) bytes?]
[(generate-key (t <dh>)) (values dhkey? bytes?)]
)]{
Random key generation.

When @scheme[t] is a @scheme[<cipher>] instance the returned values are 
a fresh key and iv for the algorithm.

When @scheme[t] is a @scheme[<pkey>] instance the @scheme[bits] argument 
specifies the size of the requested key and the returned value is a fresh @scheme[pkey]. 
For @scheme[pkey:rsa] the function optionally accepts an exponent argument 
(defaults to 65537).

When @scheme[t] is a @scheme[<digest>] instance, a fresh key for hmac is 
created.

Finally, when @scheme[t] is a @scheme[<dh>] instance the returned values are
the private @scheme[dh] key and the public key part for the exchange.
}

@subsection{Randomness}
@declare-exporting{rand.ss}

@deftogether[(
@defproc[(random-bytes (len exact-nonnegative-integer?)) bytes?]
@defproc[(random-bytes! (o bytes?) 
                        (start exact-nonnegative-integer? 0)
                        (end exact-nonnegative-integer? (bytes-length o)))
         bytes?]
)]{
Generate cryptographically secure random data.
}

@deftogether[(
@defproc[(pseudo-random-bytes (len exact-nonnegative-integer?)) bytes?]
@defproc[(pseudo-random-bytes! (o bytes?) 
                               (start exact-nonnegative-integer? 0)
                               (end exact-nonnegative-integer? (bytes-length o)))
         bytes?]
)]{
Generate pseudorandom data (not cryptographically secure).
}

@deftogether[(
@defproc[(random-rnd-status) boolean?]
@defproc[(random-rnd-add (o bytes?)) _]
@defproc[(random-rnd-seed (o bytes?)) _]
@defproc[(random-rnd-read (f path) (len exact-nonnegative-integer?))
         integer?]
@defproc[(random-rnd-write (f path)) integer?]
@defproc[(random-rnd-filename) path?]
)]{
Query and manipulate the random entropy pool.

In general, you should not have to use these functions directly as libcrypto
automatically refreshes the entropy pool using OS-provided cryptographic 
facilities.
}


@subsection{Engine Support}
@declare-exporting{engine.ss}

@deftogether[(
@defproc[(engine-load-builtin) _]
@defproc[(engine-cleanup) _]
)]{
@scheme[engine-load-builtin] loads the builtin accelerated libcrypto engine 
implementations. 

The application must cleanup by explicitly calling @scheme[engine-cleanup] 
as there is currently no reliable way to automatically cleanup using ffi.
}

@subsection{Miscellaneous}
@defmodule*/no-declare[(crypto/util (planet vyzo/crypto/util))]
@declare-exporting{util.ss}

This module provides some additional utilities that are not exported
by the main crypto library.

@deftogether[(
@defproc[(hex (o bytes?)) bytes?]
@defproc[(unhex (o bytes)) bytes?]
)]{
hex-encode and decode a byte-string
}

@deftogether[(
@defproc[(bytes-xor (in bytes?) (key bytes?)) bytes?]
@defproc[(bytes-xor! (in bytes?) (key bytes?)) bytes?]
)]{
Compute the bitwise-xor of two byte-strings;
@scheme[bytes-xor!] computes the result in-place by mutating @scheme[in].

@scheme[key] must be at least as long as @scheme[in].
}

@defproc[(shrink-bytes (o bytes?) (len exact-nonnegative-integer?)) bytes?]{
Returns @scheme[(subbytes o len)] when @scheme[o] is longer than @scheme[len]
and  @scheme[o] otherwise.
}


@section[#:tag "examples"]{Examples}

In order to run the examples, you should first require the library and
the utilities module.

Using planet:
@schemeblock[
(require (planet vyzo/crypto) (planet vyzo/crypto/util)) 
]

Or if you have locally installed:
@schemeblock[
(require crypto crypto/util)
]

In the following we use this definition for @scheme[msg]
@schemeblock[
(define msg #"There is a cat in the box.")
]

@subsection{Message Digests}

Message digests are computed in two fundamental ways: one-shot or incrementally.

For one shot digest computations one can use the named digest functions or
the generic @scheme[digest] function:
@schemeblock[
(hex (sha1 msg))
#,(schemeresult =>) #"2f888f0fa9a7cdd78fbbb15816f492d14b252e23"
(hex (sha1 (open-input-bytes msg))) (code:comment #, @t{using a port})
#,(schemeresult =>) #"2f888f0fa9a7cdd78fbbb15816f492d14b252e23"
(hex (digest digest:sha1 msg)) (code:comment #, @t{can use a port as well})
#,(schemeresult =>) #"2f888f0fa9a7cdd78fbbb15816f492d14b252e23"
]

For incremental computation we use @scheme[digest-new], @scheme[digest-update!],
and @scheme[digest-final!]. 
@schemeblock[
(let ((dg (digest-new digest:sha1)))
  (digest-update! dg msg)
  (digest-final! dg))
#,(schemeresult =>) #"2f888f0fa9a7cdd78fbbb15816f492d14b252e23"
]

HMACs can be computed using @scheme[hmac]:
@schemeblock[
(let ((hkey (random-bytes (digest-size digest:sha1))))
  (hex (hmac digest:sha1 hkey msg)))
#,(schemeresult =>) #"8ef155b9b05d11970241401eb23678df5db44686"
]

@subsection{Ciphers}

In the following we encrypt @scheme[msg] using AES-128 (in the default cbc 
mode).

First, we need to generate a key/iv pair:
@schemeblock[
(define-values (key iv) (generate-key cipher:aes-128))
]

To encrypt and decrypt directly:
@schemeblock[
(let ((ct (encrypt cipher:aes-128 key iv msg)))
  (decrypt cipher:aes-128 key iv ct))
#,(schemeresult =>) #"There is a cat in the box."
]

To encrypt and decrypt using ports:
@schemeblock[
(let* ((cin (encrypt cipher:aes-128 key iv (open-input-bytes msg)))
       (pin (decrypt cipher:aes-128 key iv cin)))
  (read-bytes 128 pin))
#,(schemeresult =>) #"There is a cat in the box."
]

Using pipes:
@schemeblock[
(let-values (((pin) (open-input-bytes msg))
             ((cin cout) (make-pipe))
             ((pout) (open-output-bytes)))
  (encrypt cipher:aes-128 key iv pin cout)
  (close-output-port cout)
  (decrypt cipher:aes-128 key iv cin pout)
  (get-output-bytes pout))
#,(schemeresult =>) #"There is a cat in the box."
]

The pipe interface is quite flexible: @scheme[encrypt] can create a
ciphertext input-port and a plaintext output-port, while @scheme[decrypt]
can create a plaintext input-port and a ciphertext output-port. 
The ports can be connected:
@schemeblock[
(let-values (((cin pout) (encrypt cipher:aes-128 key iv))
             ((pin cout) (decrypt cipher:aes-128 key iv)))
      (write-bytes msg pout)
      (close-output-port pout)
      (write-bytes (read-bytes 128 cin) cout)
      (close-output-port cout)
      (read-bytes 128 pin))
#,(schemeresult =>) #"There is a cat in the box."
]

Finally, the most general interface is the low level interface, used internally
to implement the high level operations illustrated above.
@scheme[cipher-encrypt] and @scheme[cipher-decrypt] create cipher contexts;
the contexts can be updated incrementally with @scheme[cipher-update!], while
@scheme[cipher-final!] completes the operation.

In this vain, we can implement custom encryption and decryption functions:
@schemeblock[
(define (my-encrypt key iv)
  (lambda (ptext)
    (let ((octx (cipher-encrypt cipher:aes-128 key iv)))
      (bytes-append (cipher-update! octx ptext)
                    (cipher-final! octx)))))

(define (my-decrypt key iv)
  (lambda (ctext)
    (let ((ictx (cipher-decrypt cipher:aes-128 key iv)))
      (bytes-append (cipher-update! ictx ctext)
                    (cipher-final! ictx)))))

((my-decrypt key iv) ((my-encrypt key iv) msg))
#,(schemeresult =>) #"There is a cat in the box."
]

@subsection{Public Key Cryptography}

The public key API uses the @scheme[pkey] type to encapsulate keys:
@schemeblock[
(define privk (generate-key pkey:rsa 1024))
(define pubk (pkey->public-key privk)) (code:comment #, @t{the public key})
]

Signatures are computed using @scheme[sign] with the private key, and verified
using @scheme[verify] with the public key:
@schemeblock[
(let ((sig (sign privk digest:sha1 msg)))
  (verify pubk digest:sha1 sig msg))
#,(schemeresult =>) #t
]

The key pair can be used for direct encryption as well:
@schemeblock[
(let ((ct (encrypt/pkey pubk msg)))
  (decrypt/pkey privk ct))
#,(schemeresult =>) #"There is a cat in the box."
]

However, public keys are rarely used directly for encryption. Rather, the
key pair is used to encrypt/decrypt a @emph{sealed} key and then perform 
symmetric encryption using a cipher. This pattern is simplified using 
@scheme[encrypt/envelope] and @scheme[decrypt/envelope]:
@schemeblock[
(let-values (((skey iv ct) (encrypt/envelope pubk cipher:aes-128 msg)))
  (decrypt/envelope privk cipher:aes-128 skey iv ct))
#,(schemeresult =>) #"There is a cat in the box."
]

@subsection{Diffie-Hellman Key Exchange}

In order to perform a DH key exchange, a pair of peers each generates a key 
pair using @scheme[generate-key] and exchange the public keys.
The shared key can then be computed using @scheme[compute-key]:
@schemeblock[
(define-values (priv1 pub1) (generate-key dh:1024))
(define-values (priv2 pub2) (generate-key dh:1024))
(define sk1 (compute-key priv1 pub2))
(define sk2 (compute-key priv2 pub1))
(equal? sk1 sk2)
#,(schemeresult =>) #t
]
