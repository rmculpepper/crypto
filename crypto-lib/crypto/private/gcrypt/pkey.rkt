;; Copyright 2013 Ryan Culpepper
;; 
;; This library is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as published
;; by the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;; 
;; This library is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Lesser General Public License for more details.
;; 
;; You should have received a copy of the GNU Lesser General Public License
;; along with this library.  If not, see <http://www.gnu.org/licenses/>.

#lang racket/base
(require racket/class
         racket/match
         ffi/unsafe
         asn1
         asn1/base256
         asn1/sequence
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/catalog.rkt"
         "../common/error.rkt"
         "../rkt/pk-asn1.rkt"
         "ffi.rkt")
(provide (all-defined-out))

;; TODO: factor out common code (eg sign/verify)

(define DSA-Sig-Val
  ;; take and produce integer components as bytes
  (let ([INTEGER-as-bytes (Wrap INTEGER #:encode base256-unsigned->signed #:decode values)])
    (Sequence [r INTEGER-as-bytes]
              [s INTEGER-as-bytes])))

(define (int->mpi n)   (base256->mpi (unsigned->base256 n)))
(define (mpi->int mpi) (base256->unsigned (mpi->base256 mpi)))

(define gcrypt-read-key%
  (class* impl-base% (pk-read-key<%>)
    (inherit-field factory)
    (super-new (spec 'gcrypt-read-key))

    (define/public (read-key sk fmt)
      (define (check-bytes)
        (unless (bytes? sk)
          (crypto-error "bad value for key format\n  format: ~e\n  expected: ~s\n  got: ~e"
                        fmt 'bytes? sk)))
      (case fmt
        [(SubjectPublicKeyInfo)
         (check-bytes)
         (match (DER-decode SubjectPublicKeyInfo sk)
           ;; Note: decode w/ type checks some well-formedness properties
           [`(sequence [algorithm ,alg] [subjectPublicKey ,subjectPublicKey])
            (define alg-oid (sequence-ref alg 'algorithm))
            (define params (sequence-ref alg 'parameters #f))
            (cond [(equal? alg-oid rsaEncryption)
                   (match subjectPublicKey
                     [`(sequence [modulus ,modulus] [publicExponent ,publicExponent])
                      (define pub (make-rsa-public-key modulus publicExponent))
                      (define impl (send factory get-pk 'rsa))
                      (new gcrypt-rsa-key% (impl impl) (pub pub) (priv #f))])]
                  #|
                  [(equal? alg-oid id-dsa)
                   (match params
                     [`(sequence [p ,p] [q ,q] [g ,g])
                      (define pub (make-dsa-public-key p q g subjectPublicKey))
                      (define impl (send factory get-pk 'dsa))
                      (new gcrypt-dsa-key% (impl impl) (pub pub) (priv #f))])]
                  ;; GCrypt has no DH support.
                  [(equal? alg-oid id-ecPublicKey)
                   (match params
                     [`(namedCurve ,curve-oid)
                      (cond [(curve-oid->name curve-oid)
                             => (lambda (curve-name)
                                  (define pub (make-ec-public-key curve-name subjectPublicKey))
                                  (define impl (send factory get-pk 'ec))
                                  (new gcrypt-ec-key% (impl impl) (pub pub) (priv #f)))]
                            [else #f])]
                     [_ #f])]
                  |#
                  [else #f])]
           [_ #f])]
        [(PrivateKeyInfo)
         (check-bytes)
         (match (DER-decode PrivateKeyInfo sk)
           [`(sequence [version ,version]
                       [privateKeyAlgorithm ,alg]
                       [privateKey ,privateKey]
                       . ,_)
            (define alg-oid (sequence-ref alg 'algorithm))
            (define alg-params (sequence-ref alg 'parameters #f))
            (cond #|
                  [(equal? alg-oid rsaEncryption)
                   (match privateKey
                     [`(sequence [version 0] ;; support only two-prime keys
                                 [modulus ,n]
                                 [publicExponent ,e]
                                 [privateExponent ,d]
                                 [prime1 ,p]
                                 [prime2 ,q]
                                 [exponent1 ,a]
                                 [exponent2 ,b]
                                 [coefficient ,c]
                                 . ,_)
                      ;; Note: gcrypt requires q < p (swap if needed)
                      (define u ___) ;; p^-1 mod q
                      (define pub (make-rsa-public-key n e))
                      (define priv (make-rsa-private-key n e d p q u))
                      (define impl (send factory get-pk 'rsa))
                      (new gcrypt-rsa-key% (impl impl) (pub pub) (priv priv))])]
                  |#
                  [(equal? alg-oid id-dsa)
                   (match alg-params
                     [`(sequence [p ,p] [q ,q] [g ,g])
                      (define y  ;; g^x mod p
                        (let ([y (gcry_mpi_new)])
                          (gcry_mpi_powm y (int->mpi g) (int->mpi privateKey) (int->mpi p))
                          (mpi->int y)))
                      (define pub (make-dsa-public-key p q g y))
                      (define priv (make-dsa-private-key p q g y privateKey))
                      (define impl (send factory get-pk 'dsa))
                      (new gcrypt-dsa-key% (impl impl) (pub pub) (priv priv))])]
                  #|
                  [(equal? alg-oid id-ecPublicKey)
                   (match alg-params
                     [`(namedCurve ,curve-oid)
                      (cond [(curve-oid->name curve-oid)
                             => (lambda (curve-name)
                                  (define q (___ gcry_mpi_ec_get_point ___))
                                  (define pub (make-ec-public-key curve-name q))
                                  (define priv (make-ec-private-key curve-name q privateKey)))]
                            [else #f])])]
                  |#
                  [else #f])]
           [_ #f])]
        [else #f]))

    (define/private (make-rsa-public-key n e)
      (gcry_sexp_build "(public-key (rsa %S %S))"
                       (gcry_sexp_build "(n %M)" (int->mpi n))
                       (gcry_sexp_build "(e %M)" (int->mpi e))))

    (define/private (make-rsa-private-key n e d p q u)
      (define priv
        (gcry_sexp_build "(private-key (rsa %S %S %S %S %S %S))"
                         (gcry_sexp_build "(n %M)" (int->mpi n))
                         (gcry_sexp_build "(e %M)" (int->mpi e))
                         (gcry_sexp_build "(d %M)" (int->mpi d))
                         (gcry_sexp_build "(p %M)" (int->mpi p))
                         (gcry_sexp_build "(q %M)" (int->mpi q))
                         (gcry_sexp_build "(u %M)" (int->mpi u))))
      ;; FIXME: (gcry_pk_testkey ....)
      priv)

    (define/private (make-dsa-public-key p q g y)
      (gcry_sexp_build "(public-key (dsa %S %S %S %S))"
                       (gcry_sexp_build "(p %M)" (int->mpi p))
                       (gcry_sexp_build "(q %M)" (int->mpi q))
                       (gcry_sexp_build "(g %M)" (int->mpi g))
                       (gcry_sexp_build "(y %M)" (int->mpi y))))

    (define/private (make-dsa-private-key p q g y x)
      (define priv
        (gcry_sexp_build "(private-key (dsa %S %S %S %S %S))"
                         (gcry_sexp_build "(p %M)" (int->mpi p))
                         (gcry_sexp_build "(q %M)" (int->mpi q))
                         (gcry_sexp_build "(g %M)" (int->mpi g))
                         (gcry_sexp_build "(y %M)" (int->mpi y))
                         (gcry_sexp_build "(x %M)" (int->mpi x))))
      ;; FIXME: (gcry_pk_testkey ...)
      priv)

    (define/private (make-ec-public-key curve q)
      (gcry_sexp_build "(public-key (ecc %S %S))"
                       (gcry_sexp_build/%b "(curve %b)" curve)
                       (gcry_sexp_build/%b "(q %b)" q)))

    (define/private (make-ec-private-key curve q d)
      (define priv
        (gcry_sexp_build "(private-key (ecc %S %S %S))"
                         (gcry_sexp_build/%b "(curve %b)" curve)
                         (gcry_sexp_build/%b "(q %b)" q)
                         (gcry_sexp_build    "(d %M)" (int->mpi d))))
      ;; FIXME: (gcry_pk_testkey ....)
      priv)

    (define/private (curve-oid->name oid)
      (define name-sym
        (for/first ([entry (in-list known-curves)]
                    #:when (equal? (cdr entry) oid))
          (car entry)))
      (and (memq name-sym '(secp192r1 secp224r1 secp256r1 secp384r1 secp521r1))
           (string->bytes/latin-1 (symbol->string name-sym))))

    (define/public (read-params sp) #f)
    ))

;; ============================================================

(define gcrypt-pk-impl%
  (class* impl-base% (pk-impl<%>)
    (inherit-field spec factory)
    (super-new)

    (define/public (generate-key config)
      (err/no-direct-keygen spec))
    (define/public (generate-params config)
      (err/no-params spec))
    (define/public (can-encrypt?) #f)
    (define/public (can-sign?) #f)
    (define/public (can-key-agree?) #f)
    (define/public (has-params?) #f)

    (define/public (*generate-key keygen-sexp key-class)
      (define result (gcry_pk_genkey keygen-sexp))
      (define pub
        (or (gcry_sexp_find_token result "public-key")
            (crypto-error "failed to generate public key component")))
      (define priv
        (or (gcry_sexp_find_token result "private-key")
            (crypto-error "failed to generate private key component")))
      (new key-class (impl this) (pub pub) (priv priv)))

    (define/public (get-random-ctx)
      (define r (send factory get-random))
      (send r get-context))
    ))

;; ============================================================

(define allowed-rsa-keygen
  `((nbits ,exact-positive-integer? "exact-positive-integer?")
    (e     ,exact-positive-integer? "exact-positive-integer?")))

(define gcrypt-rsa-impl%
  (class gcrypt-pk-impl%
    (inherit-field spec factory)
    (inherit get-random-ctx
             *generate-key)
    (super-new (spec 'rsa))

    (define/override (can-encrypt?) #t)
    (define/override (can-sign?) #t)

    (define/override (generate-key config)
      (check-keygen-spec config allowed-rsa-keygen)
      (let ([nbits (or (keygen-spec-ref config 'nbits) 2048)]
            ;; e default 0 means use gcrypt default "secure and fast value"
            [e (or (keygen-spec-ref config 'e) 0)])
        (*generate-key 
         (gcry_sexp_build "(genkey (rsa %S %S))"
                          (gcry_sexp_build/%u "(nbits %u)" nbits)
                          (gcry_sexp_build/%u "(rsa-use-e %u)" e))
         gcrypt-rsa-key%)))
    ))

(define gcrypt-rsa-key%
  (class* ctx-base% (pk-key<%>)
    (init-field pub priv)
    (inherit-field impl)
    (super-new)

    (define/public (is-private?) (and priv #t))

    (define/public (get-public-key)
      (if priv (new gcrypt-rsa-key% (impl impl) (pub pub) (priv #f)) this))

    (define/public (get-params)
      (crypto-error "key parameters not supported"))

    (define/public (write-key fmt)
      (define (get-mpi sexp tag)
        (define rsa-sexp (gcry_sexp_find_token sexp "rsa"))
        (define tag-sexp (gcry_sexp_find_token rsa-sexp tag))
        (gcry_sexp_nth_mpi tag-sexp 1))
      (case fmt
        [(SubjectPublicKeyInfo)
         (DER-encode
          SubjectPublicKeyInfo
          `(sequence [algorithm
                      (sequence [algorithm ,rsaEncryption]
                                [parameters #f])]
                     [subjectPublicKey
                      (sequence [modulus ,(mpi->int (get-mpi pub "n"))]
                                [publicExponent ,(mpi->int (get-mpi pub "e"))])]))]
        #|
        [(PrivateKeyInfo)
         (unless (is-private?) (err/key-format 'rsa #f fmt))
         (DER-encode
          PrivateKeyInfo
          `(sequence [version 0]
                     [privateKeyAlgorithm
                      (sequence [algorithm ,rsaEncryption]
                                [parameters #f])]
                     [privateKey
                      (sequence [version 0]
                                [modulus ,(mpi->int (get-mpi priv "n"))]
                                [publicExponent ,(mpi->int (get-mpi priv "e"))]
                                [privateExponent ,(mpi->int (get-mpi priv "d"))]
                                [prime1 ,(mpi->int (get-mpi priv "p"))]
                                [prime2 ,(mpi->int (get-mpi priv "q"))]
                                [exponent1 ,???]
                                [exponent2 ,???]
                                [coefficient ,???])]))]
        |#
        [else (err/key-format 'rsa (is-private?) fmt)]))

    (define/public (equal-to-key? other)
      (and (is-a? other gcrypt-rsa-key%)
           (equal? (gcry_sexp->bytes pub)
                   (gcry_sexp->bytes (get-field pub other)))))

    (define/public (sign digest digest-spec pad)
      (unless (send impl can-sign?) (err/no-sign (send impl get-spec)))
      (unless priv (err/sign-requires-private))
      (check-digest digest digest-spec)
      (define padding (check-sig-padding pad))
      (define data-sexp
        (gcry_sexp_build "(data (flags %s) (hash %s %b))"
                         padding
                         (string->bytes/utf-8 (symbol->string digest-spec))
                         (cast (bytes-length digest) _uintptr _pointer)
                         digest))
      (define sig-sexp (gcry_pk_sign data-sexp priv))
      (define sig-part (gcry_sexp_find_token sig-sexp "rsa"))
      (define sig-s-part (gcry_sexp_find_token sig-part "s"))
      (define sig-data (gcry_sexp_nth_data sig-s-part 1))
      (gcry_sexp_release sig-s-part)
      (gcry_sexp_release sig-part)
      (gcry_sexp_release sig-sexp)
      (gcry_sexp_release data-sexp)
      sig-data)

    (define/private (check-digest digest digest-spec)
      (unless (= (bytes-length digest)
                 (digest-spec-size digest-spec))
        (crypto-error
         "digest wrong size\n  digest algorithm: ~s\n  expected size:  ~s\n  digest: ~e"
         digest-spec (digest-spec-size digest-spec) digest)))

    (define/private (check-sig-padding pad)
      (case pad
        [(#f pss) #"pss"]
        [(pkcs1-v1.5) #"pkcs1"]
        [else (crypto-error "RSA padding mode not supported\n  padding: ~e" pad)]))

    (define/public (verify digest digest-spec pad sig)
      (unless (send impl can-sign?) (err/no-sign (send impl get-spec)))
      (check-digest digest digest-spec)
      (define padding (check-sig-padding pad))
      (define data-sexp
        (gcry_sexp_build "(data (flags %s) (hash %s %b))"
                         padding
                         (string->bytes/utf-8 (symbol->string digest-spec))
                         (cast (bytes-length digest) _uintptr _pointer)
                         digest))
      (define sig-sexp
        (gcry_sexp_build "(sig-val (rsa (s %b)))"
                         (cast (bytes-length sig) _uintptr _pointer)
                         sig))
      (define result (gcry_pk_verify sig-sexp data-sexp pub))
      (gcry_sexp_release sig-sexp)
      (gcry_sexp_release data-sexp)
      result)

    (define/public (encrypt data pad)
      (unless (send impl can-encrypt?) (err/no-encrypt (send impl get-spec)))
      (define padding (check-enc-padding pad))
      (define data-sexp
        (gcry_sexp_build "(data (flags %s) (value %b))"
                         padding
                         (cast (bytes-length data) _uintptr _pointer) ;; bleh, hack
                         data))
      (define enc-sexp (gcry_pk_encrypt data-sexp pub))
      (define enc-part (gcry_sexp_find_token enc-sexp "rsa"))
      (define enc-a-part (gcry_sexp_find_token enc-part "a"))
      (define enc-mpi (gcry_sexp_nth_mpi enc-a-part 1))
      (define enc-data (mpi->base256 enc-mpi))
      (gcry_mpi_release enc-mpi)
      (gcry_sexp_release enc-a-part)
      (gcry_sexp_release enc-part)
      (gcry_sexp_release enc-sexp)
      (gcry_sexp_release data-sexp)
      enc-data)

    (define/public (decrypt data pad)
      (unless (send impl can-encrypt?) (err/no-encrypt (send impl get-spec)))
      (unless priv (err/decrypt-requires-private))
      (define padding (check-enc-padding pad))
      (define enc-sexp
        (gcry_sexp_build "(enc-val (flags %s) (rsa (a %M)))"
                         padding
                         (int->mpi (base256->unsigned data))))
      (define dec-sexp
        (or (gcry_pk_decrypt enc-sexp priv)
            (crypto-error "RSA decryption failed")))
      (define dec-data (gcry_sexp_nth_data dec-sexp 1))
      (gcry_sexp_release enc-sexp)
      (gcry_sexp_release dec-sexp)
      dec-data)

    (define/private (check-enc-padding pad)
      (case pad
        [(#f oaep) #"oaep"]
        [(pkcs1-v1.5) #"pkcs1"]
        [else (crypto-error "RSA padding mode not supported\n  padding: ~e" pad)]))

    (define/public (compute-secret peer-pubkey0)
      (crypto-error "not supported"))
    ))


;; ============================================================

;; TODO: implement DSA param support

(define allowed-dsa-keygen
  `((nbits ,exact-positive-integer? "exact-positive-integer?")
    (qbits ,(lambda (x) (member x '(160 256))) "(or/c 160 256)")))

(define gcrypt-dsa-impl%
  (class gcrypt-pk-impl%
    (inherit-field spec factory)
    (inherit get-random-ctx *generate-key)
    (super-new (spec 'dsa))

    (define/override (can-encrypt?) #f)
    (define/override (can-sign?) #t)

    (define/override (generate-key config)
      (check-keygen-spec config allowed-dsa-keygen)
      (let ([nbits (or (keygen-spec-ref config 'nbits) 2048)]
            [qbits (or (keygen-spec-ref config 'qbits) 256)])
        (*generate-key
         (gcry_sexp_build "(genkey (dsa %S %S))" 
                          (gcry_sexp_build/%u "(nbits %u)" nbits)
                          (gcry_sexp_build/%u "(qbits %u)" qbits))
         gcrypt-dsa-key%)))
    ))

(define gcrypt-dsa-key%
  (class* ctx-base% (pk-key<%>)
    (init-field pub priv)
    (inherit-field impl)
    (super-new)

    (define/public (is-private?) (and priv #t))

    (define/public (get-public-key)
      (if priv (new gcrypt-dsa-key% (impl impl) (pub pub) (priv #f)) this))

    (define/public (get-params)
      (crypto-error "key parameters not supported"))

    (define/public (write-key fmt)
      (define (get-mpi sexp tag)
        (define rsa-sexp (gcry_sexp_find_token sexp "dsa"))
        (define tag-sexp (gcry_sexp_find_token rsa-sexp tag))
        (gcry_sexp_nth_mpi tag-sexp 1))
      (case fmt
        [(SubjectPublicKeyInfo)
         (DER-encode
          SubjectPublicKeyInfo
          `(sequence [algorithm
                      (sequence [algorithm ,id-dsa]
                                [parameters
                                 (sequence [p ,(mpi->int (get-mpi pub "p"))]
                                           [q ,(mpi->int (get-mpi pub "q"))]
                                           [g ,(mpi->int (get-mpi pub "g"))])])]
                     [subjectPublicKey
                      ,(mpi->int (get-mpi pub "y"))]))]
        [(PrivateKeyInfo)
         (unless (is-private?) (err/key-format 'dsa #f fmt))
         (DER-encode
          PrivateKeyInfo
          `(sequence [version 0]
                     [privateKeyAlgorithm
                      (sequence [algorithm ,id-dsa]
                                [parameters
                                 (sequence [p ,(mpi->int (get-mpi priv "p"))]
                                           [q ,(mpi->int (get-mpi priv "q"))]
                                           [g ,(mpi->int (get-mpi priv "g"))])])]
                     [privateKey
                      ,(mpi->int (get-mpi priv "x"))]))]
        [else (err/key-format 'dsa (is-private?) fmt)]))

    (define/public (equal-to-key? other)
      (and (is-a? other gcrypt-dsa-key%)
           (equal? (gcry_sexp->bytes pub)
                   (gcry_sexp->bytes (get-field pub other)))))

    (define/public (sign digest digest-spec pad)
      (unless (send impl can-sign?) (err/no-sign (send impl get-spec)))
      (unless priv (err/sign-requires-private))
      (check-digest digest digest-spec)
      (unless (member pad '(#f))
        (crypto-error "DSA padding mode not supported\n  padding: ~e" pad))
      (define data-sexp
        (gcry_sexp_build "(data (flags raw) (value %M))"
                         (base256->mpi digest)))
      (define sig-sexp (gcry_pk_sign data-sexp priv))
      (define sig-part (gcry_sexp_find_token sig-sexp "dsa"))
      (define sig-r-part (gcry_sexp_find_token sig-part "r"))
      (define sig-r-data (gcry_sexp_nth_data sig-r-part 1))
      (define sig-s-part (gcry_sexp_find_token sig-part "s"))
      (define sig-s-data (gcry_sexp_nth_data sig-s-part 1))
      (gcry_sexp_release sig-r-part)
      (gcry_sexp_release sig-s-part)
      (gcry_sexp_release sig-part)
      (gcry_sexp_release sig-sexp)
      (gcry_sexp_release data-sexp)
      (DER-encode DSA-Sig-Val `(sequence [r ,sig-r-data] [s ,sig-s-data])))

    (define/public (verify digest digest-spec pad sig-der)
      (unless (send impl can-sign?) (err/no-sign (send impl get-spec)))
      (check-digest digest digest-spec)
      (unless (member pad '(#f))
        (crypto-error "DSA padding mode not supported\n  padding: ~e" pad))
      (define-values (r s) (der->dsa-signature-parts sig-der))
      (define data-sexp
        (gcry_sexp_build "(data (flags raw) (value %M))"
                         (base256->mpi digest)))
      (define sig-sexp
        (gcry_sexp_build "(sig-val (dsa (r %M) (s %M)))"
                         (base256->mpi r)
                         (base256->mpi s)))
      (define result (gcry_pk_verify sig-sexp data-sexp pub))
      (gcry_sexp_release sig-sexp)
      (gcry_sexp_release data-sexp)
      result)

    (define/private (der->dsa-signature-parts der)
      (match (DER-decode DSA-Sig-Val der)
        [`(sequence [r ,(? bytes? r)] [s ,(? bytes? s)])
         (values r s)]
        [_ (crypto-error 'der->dsa_signature "signature is not well-formed")]))

    (define/private (check-digest digest digest-spec)
      (unless (= (bytes-length digest)
                 (digest-spec-size digest-spec))
        (crypto-error
         "digest wrong size\n  digest algorithm: ~s\n  expected size:  ~s\n  digest: ~e"
         digest-spec (digest-spec-size digest-spec) digest)))

    (define/public (encrypt buf pad)
      (err/no-encrypt (send impl get-spec)))

    (define/public (decrypt buf pad)
      (err/no-encrypt (send impl get-spec)))

    (define/public (compute-secret peer-pubkey0)
      (crypto-error "not supported"))
    ))

;; ============================================================
;; ============================================================
;; ============================================================
