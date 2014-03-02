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

A key derivation function can be used to derive a secret key from a
master secret such as a passphrase. Typically, KDFs have additional
parameters such as salts and work factors.

KDFs are also used in password storage @cite["HtSSaP" "DUB"]. A KDF is
preferable to simple hashing (even with a salt) because the work
factor can be chosen to make exhaustively searching the space of
passwords chosen by humans (typically short and composed of
alpha-numeric characters) costly. Different KDFs have different
parameters, which may control time or space requirements.

@;{ When a password is created, a KDF is applied (with appropriate
parameters, such as a random salt and a chosen work factor) and the
result is stored. Checking the password involves running the KDF on
the candidate with the same parameters and comparing the result
against the stored value.}


@defproc[(kdf-spec? [v any/c])
         boolean?]{

Returns @racket[#t] if @racket[v] is a KDF specifier, @racket[#f]
otherwise.

A KDF specifier is one of the following:

@itemlist[

@item{@racket[(list 'pbkdf2 'hmac _digest-spec)] --- the PBKDF2
function from PKCS#5 @cite{PKCS5} using HMAC of @racket[_digest-spec]
(see @racket[digest-spec?]).}

@item{@racket['bcrypt] --- bcrypt, based on Blowfish with a modified
key schedule @cite{bcrypt}}

@item{@racket['scrypt] --- scrypt, with work factors for both time and
memory @cite{scrypt}}

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

The following parameters are recognized for @racket[(list 'pbkdf2
'hmac _digest)]:

@itemlist[
@item{@racket[(list 'iterations _iterations)] --- number of iterations of the 
@racket[(list 'hmac _digest)] pseudo-random function}
@item{@racket[(list 'key-size _key-size)] --- derive a key of
@racket[_key-size] bytes}
]

In 2000 PKCS#5 recommended a minimum of 1000 iterations; the iteration
count should be exponentially larger today.

The following parameters are recognized for @racket['scrypt]:

@itemlist[
@item{@racket[(list 'N _N)] --- the CPU/memory cost}
@item{@racket[(list 'p _p)] --- the parallelization factor}
@item{@racket[(list 'r _r)] --- the block size}
@item{@racket[(list 'key-size _key-size)] --- derive a key of
@racket[_key-size] bytes}
]

The scrypt paper (2009) used parameters such as 2@superscript{14} to
2@superscript{20} for @racket[_N], 1 for @racket[_p], and 8 for
@racket[_r].

@examples[#:eval the-eval
(kdf '(pbkdf2 hmac sha256)
     #"I am the walrus"
     #"abcd"
     '((iterations #e1e5) (key-size 32)))
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


@bibliography[
#:tag "kdf-bibliography"

@bib-entry[#:key "HtSSaP"
           #:title "How to Safely Store a Password: Use bcrypt"
           #:author "Coda Hale"
           #:url "http://codahale.com/how-to-safely-store-a-password/"]

@bib-entry[#:key "DUB"
           #:title "Don't Use bcrypt"
           #:author "Tony Arcieri"
           #:url "http://www.unlimitednovelty.com/2012/03/dont-use-bcrypt.html"]

@bib-entry[#:key "PKCS5"
           #:title "PKCS #5: Password-Based Cryptography Specification"
           #:author "B. Kaliski"
           #:url "https://tools.ietf.org/html/rfc2898"]

@bib-entry[#:key "bcrypt"
           #:title "A Future-Adaptable Password Scheme"
           #:author "Niels Provos and David Mazières"
           #:url "https://www.usenix.org/legacy/events/usenix99/provos.html"]

@bib-entry[#:key "scrypt"
           #:title "The scrypt key derivation function"
           #:author "Colin Percival"
           #:url "http://www.tarsnap.com/scrypt.html"]

]
