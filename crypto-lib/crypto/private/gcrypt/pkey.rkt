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
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/pk-common.rkt"
         "../common/catalog.rkt"
         "../common/error.rkt"
         "../common/base256.rkt"
         "../rkt/pk-asn1.rkt"
         "ffi.rkt")
(provide (all-defined-out))

(define gcrypt-curve-names '(secp192r1 secp224r1 secp256r1 secp384r1 secp521r1))

(define DSA-Sig-Val (SEQUENCE [r INTEGER] [s INTEGER]))

(define (int->mpi n)   (base256->mpi (unsigned->base256 n)))
(define (mpi->int mpi) (base256->unsigned (mpi->base256 mpi)))

(define gcrypt-read-key%
  (class pk-read-key-base%
    (inherit-field factory)
    (super-new (spec 'gcrypt-read-key))

    ;; ---- RSA ----

    (define/override (-make-pub-rsa n e)
      (define pub (make-rsa-public-key n e))
      (define impl (send factory get-pk 'rsa))
      (new gcrypt-rsa-key% (impl impl) (pub pub) (priv #f)))

    (define/private (make-rsa-public-key n e)
      (gcry_sexp_build "(public-key (rsa %S %S))"
                       (gcry_sexp_build "(n %M)" (int->mpi n))
                       (gcry_sexp_build "(e %M)" (int->mpi e))))

    (define/override (-make-priv-rsa n e d p q dp dq qInv)
      ;; Note: gcrypt requires q < p (swap if needed)
      (define-values (p* q* qInv*)
        (cond [(< p q)
               (values p q qInv)]
              [else
               (define qInv*-mpi (gcry_mpi_new))
               (or (gcry_mpi_invm qInv*-mpi (int->mpi q) (int->mpi p))
                   (crypto-error "failed to calculate qInv"))
               (values q p (mpi->int qInv*-mpi))]))
      (define pub (make-rsa-public-key n e))
      (define priv (make-rsa-private-key n e d p* q* qInv*))
      (define impl (send factory get-pk 'rsa))
      (new gcrypt-rsa-key% (impl impl) (pub pub) (priv priv)))

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

    ;; ---- DSA ----

    (define/override (-make-pub-dsa p q g y)
      (define pub (make-dsa-public-key p q g y))
      (define impl (send factory get-pk 'dsa))
      (new gcrypt-dsa-key% (impl impl) (pub pub) (priv #f)))

    (define/private (make-dsa-public-key p q g y)
      (gcry_sexp_build "(public-key (dsa %S %S %S %S))"
                       (gcry_sexp_build "(p %M)" (int->mpi p))
                       (gcry_sexp_build "(q %M)" (int->mpi q))
                       (gcry_sexp_build "(g %M)" (int->mpi g))
                       (gcry_sexp_build "(y %M)" (int->mpi y))))

    (define/override (-make-priv-dsa p q g y0 x)
      (define y  ;; g^x mod p
        (or y0
            (let ([y (gcry_mpi_new)])
              (gcry_mpi_powm y (int->mpi g) (int->mpi x) (int->mpi p))
              (mpi->int y))))
      (define pub (make-dsa-public-key p q g y))
      (define priv (make-dsa-private-key p q g y x))
      (define impl (send factory get-pk 'dsa))
      (new gcrypt-dsa-key% (impl impl) (pub pub) (priv priv)))

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

    ;; ---- EC ----

    (define/override (-make-pub-ec curve-oid q)
      (cond [(curve-oid->name curve-oid)
             => (lambda (curve-name)
                  (define pub (make-ec-public-key curve-name q))
                  (define impl (send factory get-pk 'ec))
                  (new gcrypt-ec-key% (impl impl) (pub pub) (priv #f)))]
            [else #f]))

    (define/private (make-ec-public-key curve q)
      (gcry_sexp_build "(public-key (ecc %S %S))"
                       (gcry_sexp_build/%b "(curve %b)" curve)
                       (gcry_sexp_build/%b "(q %M)" (int->mpi q))))

    (define/override (-make-priv-ec curve-oid q d)
      ;; FIXME: recover q if publicKey field not present
      ;;  -- grr, gcrypt doesn't seem to provide point<->bytes support
      (cond [(curve-oid->name curve-oid)
             => (lambda (curve-name)
                  (define pub (make-ec-public-key curve-name q))
                  (define priv (make-ec-private-key curve-name q d))
                  (define impl (send factory get-pk 'ec))
                  (new gcrypt-ec-key% (impl impl) (pub pub) (priv priv)))]
            [else #f]))

    (define/private (make-ec-private-key curve q d)
      (define priv
        (gcry_sexp_build "(private-key (ecc %S %S %S))"
                         (gcry_sexp_build/%b "(curve %b)" curve)
                         (gcry_sexp_build/%b "(q %M)" (int->mpi q))
                         (gcry_sexp_build    "(d %M)" (int->mpi d))))
      ;; FIXME: (gcry_pk_testkey ....)
      priv)

    (define/private (curve-oid->name oid)
      (define name-sym
        (for/first ([entry (in-list known-curves)]
                    #:when (equal? (cdr entry) oid))
          (car entry)))
      (and (memq name-sym gcrypt-curve-names)
           (string->bytes/latin-1 (symbol->string name-sym))))

    (define/override (read-params sp) #f)
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
    (define/public (can-encrypt? pad) #f)
    (define/public (can-sign? pad dspec) #f)
    (define/public (can-key-agree?) #f)
    (define/public (has-params?) #f)

    (define/public (*generate-key keygen-sexp key-class)
      (define result
        (or (gcry_pk_genkey keygen-sexp)
            (crypto-error "failed to generate key")))
      (define pub
        (or (gcry_sexp_find_token result "public-key")
            (crypto-error "failed to generate public key component")))
      (define priv
        (or (gcry_sexp_find_token result "private-key")
            (crypto-error "failed to generate private key component")))
      (new key-class (impl this) (pub pub) (priv priv)))

    (define/public (-known-digest? dspec)
      (or (not dspec) (and (send factory get-digest dspec) #t)))
    ))

(define gcrypt-pk-key%
  (class pk-key-base%
    (init-field pub priv)
    (inherit-field impl)
    (super-new)

    (define/override (is-private?) (and priv #t))

    (define/override (get-public-key)
      (if priv (new this% (impl impl) (pub pub) (priv #f)) this))

    (define/override (get-params)
      (crypto-error "key parameters not supported"))

    (define/override (equal-to-key? other)
      (and (is-a? other gcrypt-pk-key%)
           (equal? (gcry_sexp->bytes pub)
                   (gcry_sexp->bytes (get-field pub other)))))

    (define/override (-sign digest digest-spec pad)
      (check-sig-pad pad)
      (define data-sexp (sign-make-data-sexp digest digest-spec pad))
      (define sig-sexp (gcry_pk_sign data-sexp priv))
      (define result (sign-unpack-sig-sexp sig-sexp))
      (gcry_sexp_release sig-sexp)
      (gcry_sexp_release data-sexp)
      result)

    (define/override (-verify digest digest-spec pad sig)
      (check-sig-pad pad)
      (define data-sexp (sign-make-data-sexp digest digest-spec pad))
      (define sig-sexp (verify-make-sig-sexp sig))
      (define result (gcry_pk_verify sig-sexp data-sexp pub))
      (gcry_sexp_release sig-sexp)
      (gcry_sexp_release data-sexp)
      result)

    (abstract sign-make-data-sexp
              sign-unpack-sig-sexp
              verify-make-sig-sexp
              check-sig-pad)
    ))

;; ============================================================

(define allowed-rsa-keygen
  `((nbits ,exact-positive-integer? "exact-positive-integer?")
    (e     ,exact-positive-integer? "exact-positive-integer?")))

(define gcrypt-rsa-impl%
  (class gcrypt-pk-impl%
    (inherit-field spec factory)
    (inherit -known-digest? *generate-key)
    (super-new (spec 'rsa))

    (define/override (can-encrypt? pad) (memq pad '(#f pkcs1-v1.5 oaep)))
    (define/override (can-sign? pad dspec)
      (and (memq pad '(#f pkcs1-v1.5)) (-known-digest? dspec)))

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
  (class gcrypt-pk-key%
    (inherit-field pub priv impl)
    (inherit is-private?)
    (super-new)

    (define/override (write-key fmt)
      (define (get-mpi sexp tag)
        (define rsa-sexp (gcry_sexp_find_token sexp "rsa"))
        (define tag-sexp (gcry_sexp_find_token rsa-sexp tag))
        (gcry_sexp_nth_mpi tag-sexp 1))
      (case fmt
        [(SubjectPublicKeyInfo)
         (asn1->bytes/DER
          SubjectPublicKeyInfo
          (hasheq 'algorithm (hasheq 'algorithm rsaEncryption 'parameters #f)
                  'subjectPublicKey (hasheq 'modulus (mpi->int (get-mpi pub "n"))
                                            'publicExponent (mpi->int (get-mpi pub "e")))))]
        [(PrivateKeyInfo)
         (unless (is-private?) (err/key-format 'rsa #f fmt))
         (asn1->bytes/DER
          PrivateKeyInfo
          (hasheq 'version 0
                  'privateKeyAlgorithm (hasheq 'algorithm rsaEncryption 'parameters #f)
                  'privateKey (get-RSAPrivateKey priv)))]
        [(RSAPrivateKey)
         (unless (is-private?) (err/key-format 'rsa #f fmt))
         (asn1->bytes/DER RSAPrivateKey (get-RSAPrivateKey priv))]
        [else (err/key-format 'rsa (is-private?) fmt)]))

    (define/private (get-RSAPrivateKey priv)
      (define (get-mpi sexp tag)
        (define rsa-sexp (gcry_sexp_find_token sexp "rsa"))
        (define tag-sexp (gcry_sexp_find_token rsa-sexp tag))
        (gcry_sexp_nth_mpi tag-sexp 1))
      (define n-mpi (get-mpi priv "n"))
      (define e-mpi (get-mpi priv "e"))
      (define d-mpi (get-mpi priv "d"))
      (define p-mpi (get-mpi priv "p"))
      (define q-mpi (get-mpi priv "q"))
      (define tmp (gcry_mpi_new))
      (define dp-mpi (gcry_mpi_new))
      (gcry_mpi_sub_ui tmp p-mpi 1)
      (or (gcry_mpi_invm dp-mpi e-mpi tmp)
          (crypto-error "failed to calculate dP"))
      (define dq-mpi (gcry_mpi_new))
      (gcry_mpi_sub_ui tmp q-mpi 1)
      (or (gcry_mpi_invm dq-mpi e-mpi tmp)
          (crypto-error "failed to calculate dQ"))
      (define qInv-mpi (gcry_mpi_new))
      (or (gcry_mpi_invm qInv-mpi p-mpi q-mpi)
          (crypto-error "failed to calculate qInv"))
      (hasheq 'version 0
              'modulus (mpi->int n-mpi)
              'publicExponent (mpi->int e-mpi)
              'privateExponent (mpi->int d-mpi)
              'prime1 (mpi->int p-mpi)
              'prime2 (mpi->int q-mpi)
              'exponent1 (mpi->int dp-mpi)
              'exponent2 (mpi->int dq-mpi)
              'coefficient (mpi->int qInv-mpi)))

    (define/override (sign-make-data-sexp digest digest-spec pad)
      (define padding (check-sig-pad pad))
      (gcry_sexp_build "(data (flags %s) (hash %s %b))"
                       padding
                       (string->bytes/utf-8 (symbol->string digest-spec))
                       (cast (bytes-length digest) _uintptr _pointer)
                       digest))

    (define/override (sign-unpack-sig-sexp sig-sexp)
      (define sig-part (gcry_sexp_find_token sig-sexp "rsa"))
      (define sig-s-part (gcry_sexp_find_token sig-part "s"))
      (define sig-data (gcry_sexp_nth_data sig-s-part 1))
      (gcry_sexp_release sig-s-part)
      (gcry_sexp_release sig-part)
      sig-data)

    (define/override (check-sig-pad pad)
      (case pad
        ;; FIXME: gcrypt PSS is for fixed salt length (20), incompatible with libcrypto
        ;;   gcrypt 1.7 adds option to set salt length, but still no max/auto support
        ;; [(pss) #"pss"]
        [(pkcs1-v1.5 #f) #"pkcs1"]
        [else (crypto-error "RSA padding mode not supported\n  padding: ~e" pad)]))

    (define/override (verify-make-sig-sexp sig)
      (gcry_sexp_build "(sig-val (rsa (s %b)))"
                       (cast (bytes-length sig) _uintptr _pointer)
                       sig))

    (define/override (-encrypt data pad)
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

    (define/override (-decrypt data pad)
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
    ))


;; ============================================================

;; TODO: implement DSA param support

(define allowed-dsa-keygen
  `((nbits ,exact-positive-integer? "exact-positive-integer?")
    (qbits ,(lambda (x) (member x '(160 256))) "(or/c 160 256)")))

(define gcrypt-dsa-impl%
  (class gcrypt-pk-impl%
    (inherit-field spec factory)
    (inherit -known-digest? *generate-key)
    (super-new (spec 'dsa))

    (define/override (can-sign? pad dspec)
      (and (memq pad '(#f)) (-known-digest? dspec)))

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
  (class gcrypt-pk-key%
    (inherit-field pub priv impl)
    (inherit is-private?)
    (super-new)

    (define/override (write-key fmt)
      (define (get-mpi sexp tag)
        (define dsa-sexp (gcry_sexp_find_token sexp "dsa"))
        (define tag-sexp (gcry_sexp_find_token dsa-sexp tag))
        (gcry_sexp_nth_mpi tag-sexp 1))
      (case fmt
        [(SubjectPublicKeyInfo)
         (asn1->bytes/DER
          SubjectPublicKeyInfo
          (hasheq 'algorithm
                  (hasheq 'algorithm id-dsa
                          'parameters (hasheq 'p (mpi->int (get-mpi pub "p"))
                                              'q (mpi->int (get-mpi pub "q"))
                                              'g (mpi->int (get-mpi pub "g"))))
                  'subjectPublicKey (mpi->int (get-mpi pub "y"))))]
        [(PrivateKeyInfo)
         (unless (is-private?) (err/key-format 'dsa #f fmt))
         (asn1->bytes/DER
          PrivateKeyInfo
          (hasheq 'version 0
                  'privateKeyAlgorithm
                  (hasheq 'algorithm id-dsa
                          'parameters (hasheq 'p (mpi->int (get-mpi priv "p"))
                                              'q (mpi->int (get-mpi priv "q"))
                                              'g (mpi->int (get-mpi priv "g"))))
                  'privateKey (mpi->int (get-mpi priv "x"))))]
        [else (err/key-format 'dsa (is-private?) fmt)]))

    (define/override (sign-make-data-sexp digest digest-spec pad)
      (gcry_sexp_build "(data (flags raw) (value %M))"
                       (base256->mpi digest)))

    (define/override (sign-unpack-sig-sexp sig-sexp)
      (unpack-sig-sexp sig-sexp "dsa"))

    (define/override (check-sig-pad pad)
      (unless (member pad '(#f))
        (crypto-error "DSA padding mode not supported\n  padding: ~e" pad)))

    (define/override (verify-make-sig-sexp sig-der)
      (match (bytes->asn1/DER DSA-Sig-Val sig-der)
        [(hash-table ['r (? exact-nonnegative-integer? r)]
                     ['s (? exact-nonnegative-integer? s)])
         (gcry_sexp_build "(sig-val (dsa (r %M) (s %M)))" (int->mpi r) (int->mpi s))]
        [_ (crypto-error "signature is not well-formed")]))
    ))

(define (unpack-sig-sexp sig-sexp label)
  (define sig-part (gcry_sexp_find_token sig-sexp label))
  (define sig-r-part (gcry_sexp_find_token sig-part "r"))
  (define sig-r-data (gcry_sexp_nth_data sig-r-part 1))
  (define sig-s-part (gcry_sexp_find_token sig-part "s"))
  (define sig-s-data (gcry_sexp_nth_data sig-s-part 1))
  (gcry_sexp_release sig-r-part)
  (gcry_sexp_release sig-s-part)
  (gcry_sexp_release sig-part)
  (asn1->bytes/DER DSA-Sig-Val
                   (hasheq 'r (base256->unsigned sig-r-data)
                           's (base256->unsigned sig-s-data))))

;; ============================================================

;; Problems with gcrypt EC keys:
;;  - infeasible to recover Q (public key) from private components,
;;    (easy in principle, but gcrypt seems to lack necessary functions),
;;    so can't read PrivateKeyInfo (unless pubkey included --- but seems rare?)
;;  - keygen returns key tagged "ecdh" ??!! with curve params rather than named curve (v1.5)
;;    so can't generate keys

(define allowed-ec-keygen
  `((curve ,string? "string?")))

(define gcrypt-ec-impl%
  (class gcrypt-pk-impl%
    (inherit-field spec factory)
    (inherit -known-digest? *generate-key)
    (super-new (spec 'ec))

    (define/override (can-sign? pad dspec)
      (and (memq pad '(#f)) (-known-digest? dspec)))

    (define/override (generate-key config)
      (check-keygen-spec config allowed-ec-keygen)
      (let ([curve (keygen-spec-ref config 'curve)])
        (*generate-key
         (gcry_sexp_build "(genkey (ecc (curve %s)))"
                          (string->bytes/utf-8 curve))
         gcrypt-ec-key%)))
    ))

(define gcrypt-ec-key%
  (class gcrypt-pk-key%
    (inherit-field pub priv impl)
    (inherit is-private?)
    (super-new)

    (define/override (write-key fmt)
      (define (get-data sexp tag)
        (define ec-sexp (gcry_sexp_find_token sexp "ecc"))
        (define tag-sexp (gcry_sexp_find_token ec-sexp tag))
        (gcry_sexp_nth_data tag-sexp 1))
      (define (get-key-params sexp)
        (define curve (string->symbol (bytes->string/utf-8 (get-data sexp "curve"))))
        (cond [(assq curve known-curves) => (lambda (e) (list 'namedCurve (cdr e)))]
              [else (crypto-error "unknown curve name\n  curve: ~e" curve)]))
      (case fmt
        [(SubjectPublicKeyInfo)
         (asn1->bytes/DER
          SubjectPublicKeyInfo
          (hasheq 'algorithm (hasheq 'algorithm id-ecPublicKey
                                     'parameters (get-key-params pub))
                  'subjectPublicKey (get-data pub "q")))]
        [(PrivateKeyInfo)
         (unless (is-private?) (err/key-format 'ec #f fmt))
         (asn1->bytes/DER
          PrivateKeyInfo
          (hasheq 'version 0
                  'privateKeyAlgorithm (hasheq 'algorithm id-ecPublicKey
                                               'parameters (get-key-params priv))
                  'privateKey (hasheq 'version 1
                                      'privateKey (mpi->base256 (get-mpi priv "d"))
                                      'publicKey (mpi->base256 (get-mpi priv "q")))))]
        [else (err/key-format 'ec (is-private?) fmt)]))

    (define/private (get-mpi sexp tag)
      (define ec-sexp (gcry_sexp_find_token sexp "ecc"))
      (define tag-sexp (gcry_sexp_find_token ec-sexp tag))
      (gcry_sexp_nth_mpi tag-sexp 1))

    (define/override (sign-make-data-sexp digest digest-spec pad)
      (gcry_sexp_build "(data (flags raw) (value %M))"
                       (base256->mpi digest)))

    (define/override (sign-unpack-sig-sexp sig-sexp)
      (unpack-sig-sexp sig-sexp "ecdsa"))

    (define/override (check-sig-pad pad)
      (unless (member pad '(#f))
        (crypto-error "EC padding mode not supported\n  padding: ~e" pad)))

    (define/override (verify-make-sig-sexp sig-der)
      (match (bytes->asn1/DER DSA-Sig-Val sig-der)
        [(hash-table ['r (? exact-nonnegative-integer? r)]
                     ['s (? exact-nonnegative-integer? s)])
         (gcry_sexp_build "(sig-val (ecdsa (r %M) (s %M)))" (int->mpi r) (int->mpi s))]
        [_ (crypto-error "signature is not well-formed")]))
    ))
