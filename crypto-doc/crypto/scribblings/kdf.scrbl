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
@(the-eval '(require crypto crypto/libcrypto))
@(the-eval '(crypto-factories (list libcrypto-factory)))

@title[#:tag "kdf"]{Key Derivation and Password Hashing}


@defproc[(kdf-spec? [v any/c])
         boolean?]{

Returns @racket[#t] if @racket[v] is a KDF specifier, @racket[#f]
otherwise.

A KDF specifier is one of the following:

@itemlist[

@item{@racket[(list 'pbkdf2 'hmac _digest-spec)] --- the PBKDF2
function from PKCS#5 using HMAC of @racket[_digest-spec] (see
@racket[digest-spec?]).}

@item{@racket['bcrypt]}

@item{@racket['scrypt]}

]
}

@defproc[(kdf-impl? [v any/c])
         boolean?]{

Returns @racket[#t] if @racket[v] is an implementation of a
key-derivation function, @racket[#f] otherwise.
}

@defproc[(get-kdf [k kdf-spec?]
                  [factories (or/c crypto-factory? (listof crypto-factory?))
                             (crypto-factories)])
         kdf-impl?]{

Returns an implementation of KDF @racket[k] from the given
@racket[factories]. If no factory in @racket[factories] implements
@racket[k], returns @racket[#f].
}

@defproc[(kdf [k (or/c kdf-spec? kdf-impl?)]
              [pass bytes?]
              [salt bytes?]
              [params (listof (list/c symbol? any/c)) '()])
         bytes?]{

Runs the KDF specified by @racket[k] on the password or passphrase
@racket[pass] and the given @racket[salt] and produces a derived key
(or password hash). Additional parameters such as iteration count are
passed via @racket[params].

@;{Document parameters}

@examples[#:eval the-eval
(kdf '(pbkdf2 hmac sha256)
     #"I am the walrus"
     #"abcd"
     '((iterations 100000) (key-size 32)))
]
}

@defproc[(pbkdf2-hmac [pass bytes?]
                      [salt bytes?]
                      [#:digest di digest-spec?]
                      [#:iterations iterations exact-positive-integer?]
                      [#:key-size key-size exact-positive-integer?
                                  (digest-size di)])
         bytes?]{

Finds an implementation of PBKDF2-HMAC-@racket[di] and uses it to
derive a key of @racket[key-size] bytes from @racket[pass] and
@racket[salt]. The @racket[iterations] argument controls the amount of
work done. In 2000 PKCS#5 recommended a minimum of 1000 iterations;
the iteration count should be exponentially larger today.

@examples[#:eval the-eval
(pbkdf2-hmac #"I am the walrus" #"abcd" #:digest 'sha256 #:iterations 100000)
]
}


@(close-eval the-eval)
