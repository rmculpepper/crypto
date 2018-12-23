#lang scribble/doc
@(require scribble/manual
          scribble/basic
          scribble/eval
          racket/list
          racket/runtime-path
          crypto/private/common/catalog
          (for-label racket/base
                     racket/contract
                     crypto))

@(define-runtime-path log-file "eval-logs/kdf.rktd")
@(define the-eval (make-log-based-eval log-file 'replay))
@(the-eval '(require crypto crypto/all racket/random))
@(the-eval '(crypto-factories (list argon2-factory libcrypto-factory sodium-factory)))

@title[#:tag "kdf"]{Key Derivation and Password Hashing}

A key derivation function can be used to derive keys from secret
material that is not directly suitable for use as a key, such as a
passphrase or the result of a key agreement algorithm. Differnt KDFs
have different additional parameters such as work factors and context
information fields.

KDFs with adjustable work factors are also used to store passwords
@cite["HtSSaP" "DUB"]. A KDF is preferable to a simple digest function
(even with a salt) because the work factor can be chosen to make
exhaustively searching the space of likely passwords (typically short
and composed of alpha-numeric characters) costly.


@defproc[(kdf-spec? [v any/c])
         boolean?]{

Returns @racket[#t] if @racket[v] is a KDF specifier, @racket[#f]
otherwise.

There are two groups of KDF specifiers. The following KDFs have work
factors and are suitable for producing keys from passwords and storing
passwords:

@itemlist[

@item{@racket[(list 'pbkdf2 'hmac _digest-spec)] --- the PBKDF2
function from PKCS#5 @cite{PKCS5} using HMAC of @racket[_digest-spec]
(see @racket[digest-spec?]).}

@;{@item{@racket['bcrypt] --- bcrypt, based on Blowfish with a modified
key schedule @cite{bcrypt}}}

@item{@racket['scrypt] --- scrypt, with work factors for both time and
memory @cite{scrypt}}

@item{@racket['argon2d], @racket['argon2i], @racket['argon2id] ---
variants of Argon2, designed primarily for password hashing
@cite["Argon2" "PHC"]}

]

The following KDFs are suitable for producing keys from the results of
key-agreement algorithms. They are not suitable for storing passwords.

@itemlist[

@item{@racket[(list 'hkdf _digest-spec)] --- the HKDF
extract-then-expand function @cite{HKDF}}

@item{@racket[(list 'concat _digest-spec)] --- the Concatentation
(also called One-Step) KDF from NIST SP 800-56C @cite{SP800-56C} using
a plain digest}

@item{@racket[(list 'concat 'hmac _digest-spec)] --- the
Concatentation KDF @cite{SP800-56C} using HMAC-@racket[_digest-spec]}

@item{@racket[(list 'sp800-108-counter 'hmac _digest-spec)],
@racket[(list 'sp800-108-feedback 'hmac _digest-spec)], and
@racket[(list 'sp800-108-double-pipeline 'hmac _digest-spec)] --- KDF
constructions from NIST SP 800-108 @cite{SP800-108}; this library only
supports 32-bit counters and the standard ordering of components}

@item{@racket[(list 'ans-x9.63 _digest-spec)] --- similar to the
concatenation KDF but with a different order of components, defined by
ANSI @cite{X963}}

]

@history[#:changed "1.3" @elem{Added support for @racket['hkdf],
@racket['concat], @racket['sp800-108-*], and @racket['ans-x9.63]
algorithms.}]
}


@defproc[(kdf-impl? [v any/c])
         boolean?]{

Returns @racket[#t] if @racket[v] is an implementation of a
key-derivation function, @racket[#f] otherwise.
}

@defproc[(get-kdf [k kdf-spec?]
                  [factories (or/c crypto-factory? (listof crypto-factory?))
                             (crypto-factories)])
         (or/c kdf-impl? #f)]{

Returns an implementation of KDF @racket[k] from the given
@racket[factories]. If no factory in @racket[factories] implements
@racket[k], returns @racket[#f].
}

@defproc[(kdf [k (or/c kdf-spec? kdf-impl?)]
              [pass bytes?]
              [salt (or/c bytes? #f)]
              [params (listof (list/c symbol? any/c)) '()])
         bytes?]{

Runs the KDF specified by @racket[k] on the password or passphrase
@racket[pass] and the given @racket[salt] and produces a derived key
(or password hash). Additional parameters such as iteration count are
passed via @racket[params].

The salt must be a bytestring (@racket[bytes?]) except in the
following cases: if the KDF is @racket['ans-x9.63], @racket['concat]
with a digest, @racket['sp800-108-counter], or
@racket['sp800-108-double-pipeline], then @racket[salt] must be
@racket[#f]; if the KDF is @racket['hkdf] or @racket['concat] with
HMAC, then @racket[salt] may be either @racket[#f] or a bytestring.

The following parameters are recognized for @racket[(list 'pbkdf2
'hmac _digest)]:

@itemlist[
@item{@racket[(list 'iterations _iterations)] --- number of iterations}
@item{@racket[(list 'key-size _key-size)] --- the size of the output}
]

In 2000 PKCS#5 @cite["PKCS5"] recommended a minimum of 1000
iterations; the iteration count should be exponentially larger today.

The following parameters are recognized for @racket['scrypt]:

@itemlist[
@item{@racket[(list 'N _N)] --- the CPU/memory cost}
@item{@racket[(list 'p _p)] --- the parallelization factor}
@item{@racket[(list 'r _r)] --- the block size}
@item{@racket[(list 'key-size _key-size)] --- the size of the output}
]

In 2009 the original scrypt paper @cite["scrypt"] used parameters such
as 2@superscript{14} to 2@superscript{20} for @racket[_N], 1 for
@racket[_p], and 8 for @racket[_r].

The following parameters are recognized for @racket['argon2d],
@racket['argon2i], and @racket['argon2id]:

@itemlist[
@item{@racket[(list 't _t)] --- the time cost}
@item{@racket[(list 'm _m)] --- the memory cost (in kb)}
@item{@racket[(list 'p _p)] --- the parallelism}
@item{@racket[(list 'key-size _key-size)] -- the size of the output}
]

The following parameters are recognized for the @racket['hkdf],
@racket['concat], @racket['sp800-108-*], and @racket['asn-x9.63]
families of KDFs:

@itemlist[

@item{@racket[(list 'info _info-bytes)] --- additional contextual
information; see @cite["HKDF" "SP800-56A" "SP800-108"] for
recommendations regarding the contents and format of this field}

@item{@racket[(list 'key-size _key-size)] --- the size of the output}

]

@examples[#:eval the-eval
#:escape unsyntax
(kdf '(pbkdf2 hmac sha256)
     #"I am the eggman"
     (crypto-random-bytes 16)
     '((iterations #e1e5) (key-size 32)))
(kdf 'argon2id
     #"I am the walrus"
     #"googoogjoob"
     '((t 100) (m 2048) (p 1) (key-size 32)))
(eval:alts
 (define pre-key (.... #, @italic{do key agreement} ....))
 (define pre-key (crypto-random-bytes 16)))
(list (kdf '(hkdf sha256) pre-key #f
           '((info #"enc") (key-size 16)))
      (kdf '(hkdf sha256) pre-key #f
           '((info #"mac") (key-size 16))))
]
}

@defproc[(pwhash [k (or/c kdf-spec? kdf-impl?)]
                 [password bytes?]
                 [config (listof (list/c symbol? any/c))])
         string?]{

Computes a ``password hash'' from @racket[password] suitable for
storage, using the KDF algorithm @racket[k]. The resulting string
contains an identifier for the algorithm as well as the parameters from
@racket[config]. The formats are intended to be compatible with
@hyperlink["https://passlib.readthedocs.io/en/stable/modular_crypt_format.html"]{Modular
Crypt Format}.

The @racket[config] parameters are nearly the same as for @racket[kdf],
with the following exceptions:

@itemlist[

@item{The @racket['scrypt] algorithm requires a parameter @racket['ln]
specifying the log (base 2) of the iteration count, instead of the
@racket['N] parameter expected by the @racket[kdf] function.}

@item{The @racket['key-size] parameter is not allowed. This library
always generates password hashes with 32 bytes of raw output (before
encoding).}
]

@examples[#:eval the-eval
(define pwcred (pwhash 'argon2id #"mypassword" '((t 1000) (m 4096) (p 1))))
pwcred
]

@history[#:added "1.2"]}

@defproc[(pwhash-verify [k (or/c kdf-impl? #f)]
                        [password bytes?]
                        [pwh string?])
         boolean?]{

Check @racket[password] against the password hash @racket[pwh].

If @racket[k] is a KDF implementation (@racket[kdf-impl?]),
@racket[pwh] must have been generated with the same KDF algorithm
(but not necessarily the same implementation); otherwise an exception
is raised. If @racket[k] is @racket[#f], then the KDF algorithm is
extracted from @racket[pwh] and the @racket[(crypto-factories)] list
is searched for an implementation; if no implementation is found an
exception is raised.

@examples[#:eval the-eval
(pwhash-verify #f #"mypassword" pwcred)
(pwhash-verify #f #"wildguess" pwcred)
]

@history[#:added "1.2"]}

@; ----------------------------------------

@defproc[(pbkdf2-hmac [di digest-spec?]
                      [pass bytes?]
                      [salt bytes?]
                      [#:iterations iterations exact-positive-integer?]
                      [#:key-size key-size exact-positive-integer?
                                  (digest-size di)])
         bytes?]{

Finds an implementation of PBKDF2-HMAC-@racket[di] using
@racket[(crypto-factories)] and uses it to derive a key of
@racket[key-size] bytes from @racket[pass] and @racket[salt]. The
@racket[iterations] argument controls the amount of work done.

@examples[#:eval the-eval
(pbkdf2-hmac 'sha256 #"I am the walrus" #"abcd" #:iterations 100000)
]
}

@defproc[(scrypt [pass bytes?]
                 [salt bytes?]
                 [#:N N exact-positive-integer?]
                 [#:p p exact-positive-integer? 1]
                 [#:r r exact-positive-integer? 8]
                 [#:key-size key-size exact-positive-integer? 32])
         bytes?]{

Finds an implementation of scrypt @cite["scrypt"] using
@racket[(crypto-factories)] and uses it to derive a key of
@racket[key-size] bytes from @racket[pass] and @racket[salt]. The
@racket[N] parameter specifies the cost factor (affecting both CPU and
memory resources).
}


@(close-eval the-eval)


@bibliography[
#:tag "kdf-bibliography"

@bib-entry[#:key "OWASP"
           #:title "Password Storage Cheat Sheet"
           #:url "https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet"]

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

@bib-entry[#:key "Argon2"
           #:title "Argon2: the memory-hard function for password hashing and other applications"
           #:author "Alex Biryukov, Daniel Dinu, and Dmitry Khovratovich"
           #:url "https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf"]

@bib-entry[#:key "PHC"
           #:title "Password Hashing Competition"
           #:url "https://password-hashing.net/"]

@bib-entry[#:key "HKDF"
           #:title "RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)"
           #:url "https://tools.ietf.org/html/rfc5869"]

@bib-entry[#:key "SP800-56A"
           #:title "NIST Special Publication 800-56A Rev. 3: Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography"
           #:url "https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final"]

@bib-entry[#:key "SP800-56C"
           #:title "NIST Special Publication 800-56C Rev. 1: Recommendation for Key-Derivation Methods in Key-Establishment Schemes"
           #:url "https://csrc.nist.gov/publications/detail/sp/800-56c/rev-1/final"]

@bib-entry[#:key "SP800-108"
           #:title "NIST Special Publication 800-108: Recommendation for Key Derivation Using Pseudorandom Functions (Revised)"
           #:url "https://csrc.nist.gov/publications/detail/sp/800-108/final"]

@bib-entry[#:key "X963"
           #:title "Public Key Cryptography for the Financial Services Industry - Key Agreement and Key Transport Using Elliptic Curve Cryptography"
           #:note @elem{ --- Not freely available. The KDF definition can be found in Section
                        3.6.1 of @cite{SEC1}.}]

]
