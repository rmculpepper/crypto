#lang scribble/doc
@(require scribble/manual
          scribble/basic
          planet/scribble
          (for-label racket/base
                     racket/contract
                     (this-package-in main)))

@title[#:tag "examples"]{Examples}

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

@section{Message Digests}

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

@section{Ciphers}

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

@section{Public Key Cryptography}

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

@section{Diffie-Hellman Key Exchange}

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
