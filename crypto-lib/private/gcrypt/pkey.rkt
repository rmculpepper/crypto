;; Copyright 2013-2018 Ryan Culpepper
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
         "../common/error.rkt"
         "../common/base256.rkt"
         "../rkt/pk-asn1.rkt"
         "ffi.rkt")
(provide (all-defined-out))

(define gcrypt-curve-names '(secp192r1 secp224r1 secp256r1 secp384r1 secp521r1))

(define DSA-Sig-Val (SEQUENCE [r INTEGER] [s INTEGER]))

(define (int->mpi n)   (base256->mpi (unsigned->base256 n)))
(define (mpi->int mpi) (base256->unsigned (mpi->base256 mpi)))

(define (sexp-get-mpi outersexp outertag tag)
  (define sexp (gcry_sexp_find_token outersexp outertag))
  (define tag-sexp (gcry_sexp_find_token sexp tag))
  (gcry_sexp_nth_mpi tag-sexp 1))
(define (sexp-get-data outersexp outertag tag)
  (define sexp (gcry_sexp_find_token outersexp outertag))
  (define tag-sexp (gcry_sexp_find_token sexp tag))
  (gcry_sexp_nth_data tag-sexp 1))
(define (sexp-get-int outersexp outertag tag)
  (mpi->int (sexp-get-mpi outersexp outertag tag)))

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
                   (internal-error "failed to calculate qInv"))
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
      (gcry_pk_testkey priv)
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
      (gcry_pk_testkey priv)
      priv)

    ;; ---- EC ----

    (define/override (-make-pub-ec curve-oid q)
      (cond [(curve-oid->name curve-oid)
             => (lambda (curve-name)
                  (define pub (make-ec-public-key curve-name q))
                  (define impl (send factory get-pk 'ec))
                  (new gcrypt-ec-key% (impl impl) (pub pub) (priv #f)))]
            [else #f]))

    (define/private (make-ec-public-key curve qB)
      (gcry_sexp_build "(public-key (ecc %S %S))"
                       (gcry_sexp_build/%b "(curve %b)" curve)
                       (gcry_sexp_build/%b "(q %b)" qB)))

    (define/override (-make-priv-ec curve-oid qB d)
      ;; FIXME: recover q if publicKey field not present
      ;;  -- grr, gcrypt doesn't seem to provide point<->bytes support
      (cond [(curve-oid->name curve-oid)
             => (lambda (curve-name)
                  (define pub (make-ec-public-key curve-name qB))
                  (define priv (make-ec-private-key curve-name qB d))
                  (define impl (send factory get-pk 'ec))
                  (new gcrypt-ec-key% (impl impl) (pub pub) (priv priv)))]
            [else #f]))

    (define/private (make-ec-private-key curve qB d)
      (define priv
        (gcry_sexp_build "(private-key (ecc %S %S %S))"
                         (gcry_sexp_build/%b "(curve %b)" curve)
                         (gcry_sexp_build/%b "(q %b)" qB)
                         (gcry_sexp_build    "(d %M)" (int->mpi d))))
      (gcry_pk_testkey priv)
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
  (class pk-impl-base%
    (inherit-field factory)
    (super-new)

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

(define gcrypt-rsa-impl%
  (class gcrypt-pk-impl%
    (inherit-field spec factory)
    (inherit -known-digest? *generate-key)
    (super-new (spec 'rsa))

    (define/override (can-encrypt? pad) (memq pad '(#f pkcs1-v1.5 oaep)))
    (define/override (can-sign? pad dspec)
      (and (memq pad '(#f pkcs1-v1.5)) (-known-digest? dspec)))

    (define/override (generate-key config)
      (check-config config config:rsa-keygen "RSA key generation")
      (let ([nbits (config-ref config 'nbits 2048)]
            ;; e default 0 means use gcrypt default "secure and fast value"
            [e     (config-ref config 'e 0)])
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

    (define/override (-write-private-key fmt)
      (define (get-mpi tag) (sexp-get-mpi priv "rsa" tag))
      (define n-mpi (get-mpi "n"))
      (define e-mpi (get-mpi "e"))
      (define d-mpi (get-mpi "d"))
      (define p-mpi (get-mpi "p"))
      (define q-mpi (get-mpi "q"))
      (define tmp (gcry_mpi_new))
      (define dp-mpi (gcry_mpi_new))
      (gcry_mpi_sub_ui tmp p-mpi 1)
      (or (gcry_mpi_invm dp-mpi e-mpi tmp)
          (internal-error "failed to calculate dP"))
      (define dq-mpi (gcry_mpi_new))
      (gcry_mpi_sub_ui tmp q-mpi 1)
      (or (gcry_mpi_invm dq-mpi e-mpi tmp)
          (internal-error "failed to calculate dQ"))
      (define qInv-mpi (gcry_mpi_new))
      (or (gcry_mpi_invm qInv-mpi p-mpi q-mpi)
          (internal-error "failed to calculate qInv"))
      (apply encode-priv-rsa fmt
             (map mpi->int (list n-mpi e-mpi d-mpi p-mpi q-mpi dp-mpi dq-mpi qInv-mpi))))

    (define/override (-write-public-key fmt)
      (define (get-int tag) (sexp-get-int pub "rsa" tag))
      (encode-pub-rsa fmt (get-int "n") (get-int "e")))

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
        [else (err/bad-signature-pad impl pad)]))

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
            (crypto-error "decryption failed")))
      (define dec-data (gcry_sexp_nth_data dec-sexp 1))
      (gcry_sexp_release enc-sexp)
      (gcry_sexp_release dec-sexp)
      dec-data)

    (define/private (check-enc-padding pad)
      (case pad
        [(#f oaep) #"oaep"]
        [(pkcs1-v1.5) #"pkcs1"]
        [else (err/bad-encrypt-pad impl pad)]))
    ))


;; ============================================================

;; TODO: implement DSA param support

(define allowed-dsa-keygen
  `((nbits #f ,exact-positive-integer? "exact-positive-integer?")
    (qbits #f ,(lambda (x) (member x '(160 256))) "(or/c 160 256)")))

(define gcrypt-dsa-impl%
  (class gcrypt-pk-impl%
    (inherit-field spec factory)
    (inherit -known-digest? *generate-key)
    (super-new (spec 'dsa))

    (define/override (can-sign? pad dspec)
      (and (memq pad '(#f)) (-known-digest? dspec)))

    (define/override (generate-key config)
      (check-config config allowed-dsa-keygen "DSA key generation")
      (let ([nbits (config-ref config 'nbits 2048)]
            [qbits (config-ref config 'qbits 256)])
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

    (define/override (-write-private-key fmt)
      (define (get-int tag) (sexp-get-int priv "dsa" tag))
      (apply encode-priv-dsa fmt (map get-int '("p" "q" "g" "y" "x"))))

    (define/override (-write-public-key fmt)
      (define (get-int tag) (sexp-get-int pub "dsa" tag))
      (apply encode-pub-dsa fmt (map get-int '("p" "q" "g" "y"))))

    (define/override (sign-make-data-sexp digest digest-spec pad)
      (gcry_sexp_build "(data (flags raw) (value %M))"
                       (base256->mpi digest)))

    (define/override (sign-unpack-sig-sexp sig-sexp)
      (unpack-sig-sexp sig-sexp "dsa"))

    (define/override (check-sig-pad pad)
      (unless (member pad '(#f))
        (err/bad-signature-pad impl pad)))

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

(define gcrypt-ec-impl%
  (class gcrypt-pk-impl%
    (inherit-field spec factory)
    (inherit -known-digest? *generate-key)
    (super-new (spec 'ec))

    (define/override (can-sign? pad dspec)
      (and (memq pad '(#f)) (-known-digest? dspec)))

    (define/override (generate-key config)
      (check-config config config:ec-paramgen "EC key generation")
      (let ([curve (config-ref config 'curve)])
        (*generate-key
         (gcry_sexp_build "(genkey (ecc (curve %s)))"
                          (let ([curve (if (symbol? curve) (symbol->string curve) curve)])
                            (string->bytes/utf-8 curve)))
         gcrypt-ec-key%)))
    ))

(define gcrypt-ec-key%
  (class gcrypt-pk-key%
    (inherit-field pub priv impl)
    (inherit is-private?)
    (super-new)

    (define/override (-write-private-key fmt)
      (define curve-oid (get-curve-oid priv))
      (and curve-oid
           (let ([qB (sexp-get-data priv "ecc" "q")]
                 [d (sexp-get-int priv "ecc" "d")])
             (encode-priv-ec fmt curve-oid qB d))))

    (define/override (-write-public-key fmt)
      (define curve-oid (get-curve-oid pub))
      (and curve-oid
           (let ([qB (sexp-get-data pub "ecc" "q")])
             (encode-pub-ec fmt curve-oid qB))))

    (define/private (get-curve-oid sexp)
      (define curve (string->symbol (bytes->string/utf-8 (sexp-get-data sexp "ecc" "curve"))))
      (cond [(assq (curve-alias->name curve) known-curves) => cdr] [else #f]))

    (define/private (curve-alias->name curve-name)
      (case curve-name
        ['|NIST P-192| 'secp192r1]
        ['|NIST P-224| 'secp224r1]
        ['|NIST P-256| 'secp256r1]
        ['|NIST P-384| 'secp384r1]
        ['|NIST P-521| 'secp521r1]
        [else curve-name]))

    (define/override (sign-make-data-sexp digest digest-spec pad)
      ;; When the digest is larger than the bits of the EC field, gcrypt is
      ;; *supposed* to truncate it, but it doesn't seem to work. The gcrypt
      ;; source code seems to want to do the right thing (_gcry_ecc_ecdsa_sign
      ;; calls _gcry_dsa_normalize_hash), but it just doesn't work (that is, it
      ;; works when gcrypt both signs and verifies, but it doesn't interoperate
      ;; with libcrypto or nettle). I've tried
      ;;  - using %b to insert the data
      ;;  - using %M with an mpi created using gcry_mpi_set_opaque_copy
      ;; and neither worked. So let's try pre-truncating long data.
      (define qbits (gcry_pk_get_nbits pub))
      (define digest* (if (> (* 8 (bytes-length digest)) qbits)
                          (subbytes digest 0 (quotient (+ qbits 7) 8))
                          digest))
      (gcry_sexp_build "(data (flags raw) (value %M))" (base256->mpi digest*)))

    (define/override (sign-unpack-sig-sexp sig-sexp)
      (unpack-sig-sexp sig-sexp "ecdsa"))

    (define/override (check-sig-pad pad)
      (unless (member pad '(#f))
        (err/bad-signature-pad impl pad)))

    (define/override (verify-make-sig-sexp sig-der)
      (match (bytes->asn1/DER DSA-Sig-Val sig-der)
        [(hash-table ['r (? exact-nonnegative-integer? r)]
                     ['s (? exact-nonnegative-integer? s)])
         (gcry_sexp_build "(sig-val (ecdsa (r %M) (s %M)))" (int->mpi r) (int->mpi s))]
        [_ (crypto-error "signature is not well-formed")]))
    ))

;; ============================================================

(define gcrypt-eddsa-impl%
  (class gcrypt-pk-impl%
    (inherit-field spec factory)
    (inherit -known-digest? *generate-key)
    (super-new (spec 'eddsa))

    (define/override (can-sign? pad dspec)
      (and (memq pad '(#f)) (memq dspec '(#f))))

    (define/override (generate-key config)
      (check-config config config:eddsa-keygen "EdDSA key generation")
      (define curve-name
        (case (config-ref config 'curve)
          [(ed25519) #"Ed25519"]
          [else (crypto-error "unsupported curve\n  curve: ~e"
                              (config-ref config 'curve))]))
      (*generate-key
       (gcry_sexp_build "(genkey (ecc (curve %s) (flags eddsa)))" curve-name)
       gcrypt-eddsa-key%))
    ))

(define gcrypt-eddsa-key%
  (class gcrypt-pk-key%
    (inherit-field pub priv impl)
    (inherit is-private?)
    (super-new)

    (define/override (-write-private-key fmt)
      'todo)

    (define/override (-write-public-key fmt)
      'todo)

    (define/override (sign-make-data-sexp msg _dspec pad)
      (gcry_sexp_build "(data (flags eddsa) (hash-algo sha512) (value %M))"
                       (base256->mpi msg)))

    (define/override (sign-unpack-sig-sexp sig-sexp)
      (define sig-part (gcry_sexp_find_token sig-sexp "eddsa"))
      (define sig-r-part (gcry_sexp_find_token sig-part "r"))
      (define sig-r-data (gcry_sexp_nth_data sig-r-part 1))
      (define sig-s-part (gcry_sexp_find_token sig-part "s"))
      (define sig-s-data (gcry_sexp_nth_data sig-s-part 1))
      (gcry_sexp_release sig-r-part)
      (gcry_sexp_release sig-s-part)
      (gcry_sexp_release sig-part)
      (bytes-append sig-r-data
                    (make-bytes (- 32 (bytes-length sig-r-data)) 0)
                    sig-s-data
                    (make-bytes (- 32 (bytes-length sig-s-data)) 0)))

    (define/override (check-sig-pad pad)
      (unless (member pad '(#f))
        (err/bad-signature-pad impl pad)))

    (define/override (verify-make-sig-sexp sig-bytes)
      (unless (= (bytes-length sig-bytes) 64)
        (crypto-error "signature is not well-formed"))
      (gcry_sexp_build "(sig-val (eddsa (r %M) (s %M)))"
                       (base256->mpi (subbytes sig-bytes 0 32))
                       (base256->mpi (subbytes sig-bytes 32 64))))
    ))
