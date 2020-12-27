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
         "../common/catalog.rkt"
         "../common/common.rkt"
         "../common/pk-common.rkt"
         "../common/error.rkt"
         "../common/base256.rkt"
         "ffi.rkt")
(provide (all-defined-out))

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
    (super-new (spec 'gcrypt-read-key))))

;; ============================================================

(define gcrypt-pk-impl%
  (class pk-impl-base%
    (inherit-field factory)
    (super-new)

    (define/public (-generate-keypair keygen-sexp)
      (define result
        (or (gcry_pk_genkey keygen-sexp)
            (crypto-error "failed to generate key")))
      (define pub
        (or (gcry_sexp_find_token result "public-key")
            (crypto-error "failed to generate public key component")))
      (define priv
        (or (gcry_sexp_find_token result "private-key")
            (crypto-error "failed to generate private key component")))
      (values pub priv))

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
           (let ([d1 (send this write-key 'rkt-public)]
                 [d2 (send other write-key 'rkt-public)])
             (and d1 d2 (equal? d1 d2)))))

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
    (inherit -known-digest? -generate-keypair)
    (super-new (spec 'rsa))

    (define/override (can-encrypt? pad) (memq pad '(#f pkcs1-v1.5 oaep)))
    (define/override (can-sign? pad) (memq pad '(#f pkcs1-v1.5)))
    (define/override (can-sign2? pad dspec) (-known-digest? dspec))

    (define/override (generate-key config)
      (define-values (nbits e)
        (check/ref-config '(nbits e) config config:rsa-keygen "RSA key generation"))
      (let (;; e default 0 means use gcrypt default "secure and fast value"
            [e (or e 0)])
        (define-values (pub priv)
          (-generate-keypair
           (gcry_sexp_build "(genkey (rsa %S %S))"
                            (gcry_sexp_build/%u "(nbits %u)" nbits)
                            (gcry_sexp_build/%u "(rsa-use-e %u)" e))))
        (new gcrypt-rsa-key% (impl this) (pub pub) (priv priv))))

    ;; ----

    (define/override (make-public-key n e)
      (define pub (make-rsa-public-key n e))
      (new gcrypt-rsa-key% (impl this) (pub pub) (priv #f)))

    (define/private (make-rsa-public-key n e)
      (gcry_sexp_build "(public-key (rsa %S %S))"
                       (gcry_sexp_build "(n %M)" (int->mpi n))
                       (gcry_sexp_build "(e %M)" (int->mpi e))))

    (define/override (make-private-key n e d p q dp dq qInv)
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
      (new gcrypt-rsa-key% (impl this) (pub pub) (priv priv)))

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

(define gcrypt-dsa-impl%
  (class gcrypt-pk-impl%
    (inherit-field spec factory)
    (inherit -known-digest? -generate-keypair)
    (super-new (spec 'dsa))

    (define/override (can-sign? pad) (memq pad '(#f)))

    (define/override (generate-key config)
      (define-values (nbits qbits)
        (check/ref-config '(nbits qbits) config config:dsa-paramgen "DSA parameters generation"))
      (let ([qbits (or qbits 256)])
        (define-values (pub priv)
          (-generate-keypair
           (gcry_sexp_build "(genkey (dsa %S %S))"
                            (gcry_sexp_build/%u "(nbits %u)" nbits)
                            (gcry_sexp_build/%u "(qbits %u)" qbits))))
        (new gcrypt-dsa-key% (impl this) (pub pub) (priv priv))))

    ;; ----

    (define/override (make-public-key p q g y)
      (define pub (make-dsa-public-key p q g y))
      (new gcrypt-dsa-key% (impl this) (pub pub) (priv #f)))

    (define/private (make-dsa-public-key p q g y)
      (gcry_sexp_build "(public-key (dsa %S %S %S %S))"
                       (gcry_sexp_build "(p %M)" (int->mpi p))
                       (gcry_sexp_build "(q %M)" (int->mpi q))
                       (gcry_sexp_build "(g %M)" (int->mpi g))
                       (gcry_sexp_build "(y %M)" (int->mpi y))))

    (define/override (make-private-key p q g y0 x)
      (define y  ;; g^x mod p
        (or y0
            (let ([y (gcry_mpi_new)])
              (gcry_mpi_powm y (int->mpi g) (int->mpi x) (int->mpi p))
              (mpi->int y))))
      (define pub (make-dsa-public-key p q g y))
      (define priv (make-dsa-private-key p q g y x))
      (define impl (send factory get-pk 'dsa))
      (new gcrypt-dsa-key% (impl this) (pub pub) (priv priv)))

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
    (inherit -known-digest? -generate-keypair)
    (super-new (spec 'ec))

    (define/override (can-sign? pad) (memq pad '(#f)))
    (define/override (can-key-agree?) #t)
    (define/override (has-params?) #t)

    (define/override (generate-params config)
      (check-config config config:ec-paramgen "EC parameter generation")
      (define curve (config-ref config 'curve))
      (curve->params curve))

    (define/public (curve->params curve)
      (define curve* (alias->curve-name curve))
      (unless (memq curve* gcrypt-curves)
        (err/no-curve curve this))
      (new gcrypt-ec-params% (impl this) (curve curve*)))

    (define/public (generate-key-from-params params)
      (define curve (send params get-curve))
      (define-values (pub priv)
        (-generate-keypair
         (gcry_sexp_build "(genkey (ecc (curve %s)))"
                          (let ([curve (if (symbol? curve) (symbol->string curve) curve)])
                            (string->bytes/utf-8 curve)))))
      (new gcrypt-ec-key% (impl this) (pub pub) (priv priv)))

    ;; ----

    (define/override (make-params curve-oid)
      (curve->params (curve-oid->name curve-oid)))

    (define/override (make-public-key curve-oid qB)
      (cond [(curve-oid->name-string curve-oid)
             => (lambda (curve-name)
                  (check-ec-q curve-name qB)
                  (define pub (make-ec-public-key curve-name qB))
                  (new gcrypt-ec-key% (impl this) (pub pub) (priv #f)))]
            [else #f]))

    (define/private (make-ec-public-key curve qB)
      (gcry_sexp_build "(public-key (ecc %S %S))"
                       (gcry_sexp_build/%b "(curve %b)" curve)
                       (gcry_sexp_build/%b "(q %b)" qB)))

    (define/override (make-private-key curve-oid qB d)
      (cond [(curve-oid->name-string curve-oid)
             => (lambda (curve-name)
                  (define qB*
                    (cond [qB (begin0 qB (check-ec-q curve-name qB))]
                          [else (recompute-ec-q curve-name d)]))
                  (define pub (make-ec-public-key curve-name qB*))
                  (define priv (make-ec-private-key curve-name qB* d))
                  (new gcrypt-ec-key% (impl this) (pub pub) (priv priv)))]
            [else #f]))

    (define/private (make-ec-private-key curve qB d)
      (define priv
        (gcry_sexp_build "(private-key (ecc %S %S %S))"
                         (gcry_sexp_build/%b "(curve %b)" curve)
                         (gcry_sexp_build/%b "(q %b)" qB)
                         (gcry_sexp_build    "(d %M)" (int->mpi d))))
      (gcry_pk_testkey priv)
      priv)

    (define/private (check-ec-q curve-name qB)
      (when decode-point-ok?
        (define ec (gcry_mpi_ec_new curve-name))
        (define qpoint (gcry_mpi_point_new))
        (gcry_mpi_ec_decode_point qpoint (base256->mpi qB) ec)
        (begin0 (unless (gcry_mpi_ec_curve_point qpoint ec)
                  (err/off-curve "public key"))
          (gcry_ctx_release ec)
          (gcry_mpi_point_release qpoint))))

    (define/private (recompute-ec-q curve-name d)
      (define ec (gcry_mpi_ec_new curve-name))
      (gcry_mpi_ec_set_mpi 'd (int->mpi d) ec)
      (define pub-sexp (gcry_pubkey_get_sexp GCRY_PK_GET_PUBKEY ec))
      (begin0 (sexp-get-data pub-sexp "ecc" "q")
        (gcry_sexp_release pub-sexp)
        (gcry_ctx_release ec)))

    (define/private (curve-oid->name-string oid)
      (define name-sym (curve-oid->name oid))
      (and (memq name-sym gcrypt-curves)
           (string->bytes/latin-1 (symbol->string name-sym))))
    ))

(define gcrypt-ec-params%
  (class pk-ec-params%
    (init-field curve)
    (super-new)
    (define/override (get-curve) curve)
    ))

(define gcrypt-ec-key%
  (class gcrypt-pk-key%
    (inherit-field pub priv impl)
    (inherit is-private?)
    (super-new)

    (define/override (get-params)
      (new gcrypt-ec-params% (impl impl) (curve (get-curve))))

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

    (define/public (get-curve [sexp pub])
      (string->symbol (bytes->string/utf-8 (sexp-get-data sexp "ecc" "curve"))))
    (define/public (get-curve-oid [sexp pub])
      (curve-alias->oid (get-curve sexp)))

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

    ;; ECDH support is not documented, but described in comments in
    ;; libgcrypt/cipher/ecc.c before ecc_{encrypt,decrypt}_raw.
    (define/override (-compute-secret peer-pubkey)
      (define peer (sexp-get-data (get-field pub peer-pubkey) "ecc" "q"))
      (define dh-sexp (gcry_sexp_build/%b "(enc-val (ecdh (e %b)))" peer))
      (define sh (gcry_pk_decrypt dh-sexp priv))
      (define shb (gcry_sexp_nth_data sh 1))
      ;; shb is an EC point; decode and extract the x-coordinate
      ;; cf (unsigned->base256 (car (bytes->ec-point shb)))
      (define shblen (bytes-length shb))
      (subbytes shb 1 (+ 1 (quotient shblen 2))))

    (define/override (-compatible-for-key-agree? peer-pubkey)
      (equal? (get-curve-oid) (send peer-pubkey get-curve-oid)))

    (define/override (-convert-for-key-agree bs)
      (send impl make-public-key (get-curve-oid) bs))
    ))

;; ============================================================

(define gcrypt-eddsa-impl%
  (class gcrypt-pk-impl%
    (inherit-field spec factory)
    (inherit -known-digest? -generate-keypair)
    (super-new (spec 'eddsa))

    (define/override (can-sign? pad) (and (memq pad '(#f)) 'nodigest))
    (define/override (has-params?) #t)

    (define/override (generate-params config)
      (check-config config config:eddsa-keygen "EdDSA parameter generation")
      (curve->params (config-ref config 'curve)))

    (define/public (curve->params curve)
      (case curve
        [(ed25519) (new pk-eddsa-params% (impl this) (curve curve))]
        [else (err/no-curve curve this)]))

    (define/public (generate-key-from-params curve)
      (define curve-name
        (case curve
          [(ed25519) #"Ed25519"]
          [else (err/no-curve curve this)]))
      (define-values (pub priv)
        (-generate-keypair
         (gcry_sexp_build "(genkey (ecc (curve %s) (flags eddsa)))" curve-name)))
      (new gcrypt-ed25519-key% (impl this) (pub pub) (priv priv)))

    ;; ----

    (define/override (make-params curve)
      (case curve
        [(ed25519) (curve->params curve)]
        [else #f]))

    (define/override (make-public-key curve qB)
      (case curve
        [(ed25519)
         (define pub (make-ed25519-public-key qB))
         (new gcrypt-ed25519-key% (impl this) (pub pub) (priv #f))]
        [else #f]))

    (define/private (make-ed25519-public-key qB)
      (gcry_sexp_build "(public-key (ecc (curve Ed25519) (flags eddsa) %S %S))"
                       (gcry_sexp_build/%b "(q %b)" qB)))

    (define/override (make-private-key curve qB dB)
      ;; It doesn't seem to be possible to recover qB if it is missing,
      ;; so just fail.
      (case curve
        [(ed25519)
         (cond [qB
                (define pub (make-ed25519-public-key qB))
                (define priv (make-ed25519-private-key qB dB))
                (new gcrypt-ed25519-key% (impl this) (pub pub) (priv priv))]
               [else #f])]
        [else #f]))

    (define/private (make-ed25519-private-key qB dB)
      (define priv
        (gcry_sexp_build "(private-key (ecc (curve Ed25519) (flags eddsa) %S %S))"
                         (gcry_sexp_build/%b "(q %b)" qB)
                         (gcry_sexp_build/%b "(d %b)" dB)))
      (gcry_pk_testkey priv)
      priv)
    ))

(define gcrypt-ed25519-key%
  (class gcrypt-pk-key%
    (inherit-field pub priv impl)
    (inherit is-private?)
    (super-new)

    (define/override (get-params)
      (send impl curve->params 'ed25519))

    (define/override (-write-private-key fmt)
      (let ([qB (sexp-get-data priv "ecc" "q")]
            [dB (sexp-get-data priv "ecc" "d")])
        (encode-priv-eddsa fmt 'ed25519 qB dB)))

    (define/override (-write-public-key fmt)
      (let ([qB (sexp-get-data pub "ecc" "q")])
        (encode-pub-eddsa fmt 'ed25519 qB)))

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

;; ============================================================

(define gcrypt-ecx-impl%
  (class gcrypt-pk-impl%
    (inherit-field spec factory)
    (inherit -generate-keypair)
    (super-new (spec 'ecx))

    (define/override (can-key-agree?) #t)
    (define/override (has-params?) #t)

    (define/override (generate-params config)
      (check-config config config:ecx-keygen "EC/X parameter generation")
      (curve->params (config-ref config 'curve)))

    (define/public (curve->params curve)
      (case curve
        [(x25519) (new pk-ecx-params% (impl this) (curve curve))]
        [else (err/no-curve curve this)]))

    (define/public (generate-key-from-params curve)
      (case curve
        [(x25519)
         (define-values (pub priv)
           (-generate-keypair
            ;; without no-keytest flag, gcrypt segfaults in test_ecdh_only_keys
            (gcry_sexp_build "(genkey (ecdh (flags no-keytest) (curve Curve25519)))")))
         (new gcrypt-x25519-key% (impl this) (pub pub) (priv priv))]))

    ;; ----

    (define/override (make-params curve)
      (case curve
        [(x25519) (curve->params curve)]
        [else #f]))

    (define/override (make-public-key curve qB)
      (case curve
        [(x25519)
         (define pub (make-x25519-public-key qB))
         (new gcrypt-x25519-key% (impl this) (pub pub) (priv #f))]
        [else #f]))

    (define/private (make-x25519-public-key qB)
      (gcry_sexp_build "(public-key (ecc (curve Curve25519) %S))"
                       (gcry_sexp_build/%b "(q %b)" (raw->ec-point qB))))

    (define/override (make-private-key curve qB dB)
      ;; FIXME: recover q if publicKey field not present
      (and qB
           (case curve
             [(x25519)
              (define pub (make-x25519-public-key qB))
              (define priv (make-x25519-private-key qB dB))
              (new gcrypt-x25519-key% (impl this) (pub pub) (priv priv))]
             [else #f])))

    (define/private (make-x25519-private-key qB dB)
      (define priv
        (gcry_sexp_build "(private-key (ecc (curve Curve25519) %S %S))"
                         (gcry_sexp_build/%b "(q %b)" (raw->ec-point qB))
                         (gcry_sexp_build/%b "(d %b)" dB)))
      (gcry_pk_testkey priv)
      priv)
    ))

(define gcrypt-x25519-key%
  (class gcrypt-pk-key%
    (inherit-field pub priv impl)
    (inherit is-private?)
    (super-new)

    (define/override (get-params)
      (send impl curve->params 'x25519))

    (define/override (-write-private-key fmt)
      (let ([qB (sexp-get-data priv "ecc" "q")]
            [dB (sexp-get-data priv "ecc" "d")])
        (encode-priv-ecx fmt 'x25519 (ec-point->raw qB) dB)))

    (define/override (-write-public-key fmt)
      (let ([qB (sexp-get-data pub "ecc" "q")])
        (encode-pub-ecx fmt 'x25519 (ec-point->raw qB))))

    ;; ECDH support is not documented, but described in comments in
    ;; libgcrypt/cipher/ecc.c before ecc_{encrypt,decrypt}_raw.
    (define/override (-compute-secret peer-pubkey)
      (define peer (sexp-get-data (get-field pub peer-pubkey) "ecc" "q"))
      (define dh-sexp (gcry_sexp_build/%b "(enc-val (ecdh (e %b)))" peer))
      (define sh (gcry_pk_decrypt dh-sexp priv))
      (define shb (gcry_sexp_nth_data sh 1))
      ;; shb is (bytes #x40) + shared-secret; #x40 indicates Montgomery
      ;; point (x-coord only), cf _gcry_ecc_mont_decodepoint
      (unless (and (= (bytes-length shb) 33) (= (bytes-ref shb 0) #x40))
        (crypto-error "failed; implementation returned ill-formed result"))
      (subbytes shb 1))

    (define/override (-compatible-for-key-agree? peer-pubkey)
      #t)

    (define/override (-convert-for-key-agree bs)
      (send impl make-public-key 'x25519 bs))

    (define/override (sign-make-data-sexp) #f)
    (define/override (sign-unpack-sig-sexp) #f)
    (define/override (verify-make-sig-sexp) #f)
    (define/override (check-sig-pad) #f)
    ))

(define (ec-point->raw b)
  (unless (and (> (bytes-length b) 0) (= (bytes-ref b 0) #x40))
    (crypto-error "internal error; expected encoded Montgomery EC point"))
  (subbytes b 1))

(define (raw->ec-point b)
  (bytes-append (bytes #x40) b))
