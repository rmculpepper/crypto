;; Copyright 2014-2018 Ryan Culpepper
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
(require ffi/unsafe
         asn1
         racket/class
         racket/match
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/pk-common.rkt"
         "../common/catalog.rkt"
         "../common/error.rkt"
         "../common/base256.rkt"
         gmp gmp/unsafe
         "ffi.rkt")
(provide (all-defined-out))

(define DSA-Sig-Val (SEQUENCE [r INTEGER] [s INTEGER]))

(define (new-mpz) (mpz))
(define (integer->mpz n) (mpz n))
(define (mpz->integer z) (mpz->number z))
(define (mpz->bin z) (mpz->bytes z #f #f #t))
(define (bin->mpz buf) (bytes->mpz buf #f #t))

;; ============================================================

(define nettle-read-key%
  (class pk-read-key-base%
    (inherit-field factory)
    (super-new (spec 'gcrypt-read-key))

    ;; ---- RSA ----

    (define/override (-make-pub-rsa n e)
      (define pub (new-rsa_public_key))
      (mpz_set (rsa_public_key_struct-n pub) (integer->mpz n))
      (mpz_set (rsa_public_key_struct-e pub) (integer->mpz e))
      (unless (nettle_rsa_public_key_prepare pub) (crypto-error "bad public key"))
      (define impl (send factory get-pk 'rsa))
      (and impl (new nettle-rsa-key% (impl impl) (pub pub) (priv #f))))

    (define/override (-make-priv-rsa n e d p q dp dq qInv)
      (define pub (new-rsa_public_key))
      (define priv (new-rsa_private_key))
      (mpz_set (rsa_public_key_struct-n pub) (integer->mpz n))
      (mpz_set (rsa_public_key_struct-e pub) (integer->mpz e))
      (mpz_set (rsa_private_key_struct-d priv) (integer->mpz d))
      (mpz_set (rsa_private_key_struct-p priv) (integer->mpz p))
      (mpz_set (rsa_private_key_struct-q priv) (integer->mpz q))
      (mpz_set (rsa_private_key_struct-a priv) (integer->mpz dp))
      (mpz_set (rsa_private_key_struct-b priv) (integer->mpz dq))
      (mpz_set (rsa_private_key_struct-c priv) (integer->mpz qInv))
      (unless (nettle_rsa_public_key_prepare pub)
        (crypto-error "bad public key"))
      (unless (nettle_rsa_private_key_prepare priv)
        (crypto-error "bad private key"))
      (define impl (send factory get-pk 'rsa))
      (and impl (new nettle-rsa-key% (impl impl) (pub pub) (priv priv))))

    ;; ---- DSA ----

    (define/override (-make-pub-dsa p q g y)
      (define params (-params-dsa p q g))
      (define pub (integer->mpz y))
      (define impl (send factory get-pk 'dsa))
      (and impl (new nettle-dsa-key% (impl impl) (params params) (pub pub) (priv #f))))

    (define/override (-make-priv-dsa p q g y x)
      (define params (-params-dsa p q g))
      (define priv (integer->mpz x))
      (define pub
        (cond [y (integer->mpz y)]
              [else ;; must recompute public key, y = g^x mod p
               (define yz (new-mpz))
               (mpz_powm yz
                         (dsa_params_struct-g params)
                         priv
                         (dsa_params_struct-p params))
               yz]))
      (define impl (send factory get-pk 'dsa))
      (and impl (new nettle-dsa-key% (impl impl) (params params) (pub pub) (priv priv))))

    (define/override (-make-params-dsa p q g)
      (define impl (send factory get-pk 'dsa))
      (and impl (new nettle-dsa-params% (impl impl) (params (-params-dsa p q g)))))

    (define/private (-params-dsa p q g)
      (define params (new-dsa_params))
      (mpz_set (dsa_params_struct-p params) (integer->mpz p))
      (mpz_set (dsa_params_struct-q params) (integer->mpz q))
      (mpz_set (dsa_params_struct-g params) (integer->mpz g))
      params)

    ;; ---- EC ----

    (define/override (-make-pub-ec curve-oid qB)
      (define ecc (curve-oid->ecc curve-oid))
      (define pub (and ecc (make-ec-public-key ecc qB)))
      (cond [(and ecc pub)
             (define impl (send factory get-pk 'ec))
             (and impl (new nettle-ec-key% (impl impl) (pub pub) (priv #f)))]
            [else #f]))

    (define/override (-make-priv-ec curve-oid qB d)
      (define ecc (curve-oid->ecc curve-oid))
      (define pub (and ecc (make-ec-public-key ecc qB)))
      (cond [(and ecc pub)
             (define priv (new-ecc_scalar ecc))
             (nettle_ecc_scalar_set priv (integer->mpz d))
             (define impl (send factory get-pk 'ec))
             (and impl (new nettle-ec-key% (impl impl) (pub pub) (priv priv)))]
            [else #f]))

    (define/private (make-ec-public-key ecc qB)
      (cond [(bytes->ec-point qB)
             => (lambda (x+y)
                  (define x (integer->mpz (car x+y)))
                  (define y (integer->mpz (cdr x+y)))
                  (define pub (new-ecc_point ecc))
                  (nettle_ecc_point_set pub x y)
                  pub)]
            [else #f]))

    (define/override (-make-params-ec curve-oid)
      (define ecc (curve-oid->ecc curve-oid))
      (define impl (send factory get-pk 'ec))
      (and ecc impl (new nettle-ec-params% (impl impl) (ecc ecc))))
    ))

;; ============================================================

(define nettle-pk-impl%
  (class pk-impl-base%
    (inherit-field factory)
    (super-new)
    (define/public (get-random-ctx)
      (send factory get-random-ctx))
    ))

;; ============================================================

(define allowed-rsa-keygen
  `((nbits ,exact-positive-integer? "exact-positive-integer?")
    (e     ,exact-positive-integer? "exact-positive-integer?")))

(define nettle-rsa-impl%
  (class nettle-pk-impl%
    (inherit-field spec factory)
    (inherit get-random-ctx)
    (super-new (spec 'rsa))

    (define/override (can-encrypt? pad) (memq pad '(#f pkcs1-v1.5)))
    (define/override (can-sign? pad dspec)
      (case pad
        [(pkcs1-v1.5) (memq dspec '(#f md5 sha1 sha256 sha512))]
        [(pss) (and pss-ok? (memq dspec '(#f sha256 sha384 sha512)))]
        [(#f) #t]
        [else #f]))

    (define/override (generate-key config)
      (check-config config config:rsa-keygen "RSA key generation")
      (let ([nbits (config-ref config 'nbits 2048)]
            [e     (config-ref config 'e 65537)])
        (define pub (new-rsa_public_key))
        (define priv (new-rsa_private_key))
        (mpz_set_si (rsa_public_key_struct-e pub) e)
        (or (nettle_rsa_generate_keypair pub priv (get-random-ctx) nbits 0)
            (crypto-error "RSA key generation failed"))
        (new nettle-rsa-key% (impl this) (pub pub) (priv priv))))
    ))

(define nettle-rsa-key%
  (class pk-key-base%
    (init-field pub priv)
    (inherit-field impl)
    (inherit about)
    (super-new)

    (define/override (is-private?) (and priv #t))

    (define/override (get-public-key)
      (if priv (new nettle-rsa-key% (impl impl) (pub pub) (priv #f)) this))

    (define/override (-write-private-key fmt)
      (encode-priv-rsa fmt
                       (mpz->integer (rsa_public_key_struct-n pub))
                       (mpz->integer (rsa_public_key_struct-e pub))
                       (mpz->integer (rsa_private_key_struct-d priv))
                       (mpz->integer (rsa_private_key_struct-p priv))
                       (mpz->integer (rsa_private_key_struct-q priv))
                       (mpz->integer (rsa_private_key_struct-a priv))
                       (mpz->integer (rsa_private_key_struct-b priv))
                       (mpz->integer (rsa_private_key_struct-c priv))))

    (define/override (-write-public-key fmt)
      (encode-pub-rsa fmt
                      (mpz->integer (rsa_public_key_struct-n pub))
                      (mpz->integer (rsa_public_key_struct-e pub))))

    (define/override (equal-to-key? other)
      (and (is-a? other nettle-rsa-key%)
           (= (rsa_public_key_struct-size pub)
              (rsa_public_key_struct-size (get-field pub other)))
           (mpz=? (rsa_public_key_struct-n pub)
                  (rsa_public_key_struct-n (get-field pub other)))
           (mpz=? (rsa_public_key_struct-e pub)
                  (rsa_public_key_struct-e (get-field pub other)))))

    (define/override (-sign digest digest-spec pad)
      (define randctx (send impl get-random-ctx))
      (define sigz (new-mpz))
      (define signed-ok?
        (case pad
          [(pkcs1-v1.5 #f)
           (case digest-spec
             [(md5)    (nettle_rsa_md5_sign_digest_tr    pub priv randctx digest sigz)]
             [(sha1)   (nettle_rsa_sha1_sign_digest_tr   pub priv randctx digest sigz)]
             [(sha256) (nettle_rsa_sha256_sign_digest_tr pub priv randctx digest sigz)]
             [(sha512) (nettle_rsa_sha512_sign_digest_tr pub priv randctx digest sigz)]
             [else (nosupport/digest+pad "signing" digest-spec pad)])]
          [(pss)
           (unless pss-ok? (err/bad-signature-pad impl pad))
           (define saltlen (digest-spec-size digest-spec))
           (define salt (crypto-random-bytes saltlen))
           (case digest-spec
             [(sha256) (nettle_rsa_pss_sha256_sign_digest_tr pub priv randctx saltlen salt digest sigz)]
             [(sha384) (nettle_rsa_pss_sha384_sign_digest_tr pub priv randctx saltlen salt digest sigz)]
             [(sha512) (nettle_rsa_pss_sha512_sign_digest_tr pub priv randctx saltlen salt digest sigz)]
             [else (nosupport/digest+pad "signing" digest-spec pad)])]
          [else (err/bad-signature-pad impl pad)]))
      (unless signed-ok? (crypto-error "signing failed\n  key: ~a" (about)))
      (mpz->bin sigz))

    (define/private (nosupport/digest+pad op digest-spec pad)
      (crypto-error (string-append "unsupported digest and padding combination for ~a"
                                   "\n  digest: ~s\n  padding: ~s\n  key: ~a")
                    op digest-spec (or pad 'pkcs1-v1.5) (about)))

    (define/override (-verify digest digest-spec pad sig)
      (define sigz (bin->mpz sig))
      (define verified-ok?
        (case pad
          [(pkcs1-v1.5 #f)
           (case digest-spec
             [(md5)    (nettle_rsa_md5_verify_digest    pub digest sigz)]
             [(sha1)   (nettle_rsa_sha1_verify_digest   pub digest sigz)]
             [(sha256) (nettle_rsa_sha256_verify_digest pub digest sigz)]
             [(sha512) (nettle_rsa_sha512_verify_digest pub digest sigz)]
             [else (nosupport/digest+pad "verification" digest-spec pad)])]
          [(pss)
           (unless pss-ok? (err/bad-signature-pad impl pad))
           (define saltlen (digest-spec-size digest-spec))
           (case digest-spec
             [(sha256) (nettle_rsa_pss_sha256_verify_digest pub saltlen digest sigz)]
             [(sha384) (nettle_rsa_pss_sha384_verify_digest pub saltlen digest sigz)]
             [(sha512) (nettle_rsa_pss_sha512_verify_digest pub saltlen digest sigz)]
             [else (nosupport/digest+pad "verification" digest-spec pad)])]
          [else (err/bad-signature-pad impl pad)]))
      verified-ok?)

    (define/override (-encrypt buf pad)
      (case pad
        [(pkcs1-v1.5 #f)
         (define enc-z (new-mpz))
         (or (nettle_rsa_encrypt pub (send impl get-random-ctx) buf enc-z)
             (crypto-error "encyption failed"))
         (mpz->bin enc-z)]
        [else (err/bad-encrypt-pad impl pad)]))

    (define/override (-decrypt buf pad)
      (case pad
        [(pkcs1-v1.5 #f)
         (define randctx (send impl get-random-ctx))
         (define enc-z (bin->mpz buf))
         (define dec-buf (make-bytes (rsa_public_key_struct-size pub)))
         (define dec-size (nettle_rsa_decrypt_tr pub priv randctx dec-buf enc-z))
         (unless dec-size (crypto-error "decryption failed"))
         (shrink-bytes dec-buf dec-size)]
        [else (err/bad-encrypt-pad impl pad)]))
    ))

;; ============================================================
;; DSA

(define (dsa_signature->der sig)
  (asn1->bytes/DER DSA-Sig-Val
    (hasheq 'r (mpz->integer (dsa_signature_struct-r sig))
            's (mpz->integer (dsa_signature_struct-s sig)))))

(define (der->dsa_signature der)
  (match (bytes->asn1/DER DSA-Sig-Val der)
    [(hash-table ['r (? exact-nonnegative-integer? r)]
                 ['s (? exact-nonnegative-integer? s)])
     (define sig (new-dsa_signature))
     (mpz_set (dsa_signature_struct-r sig) (integer->mpz r))
     (mpz_set (dsa_signature_struct-s sig) (integer->mpz s))
     sig]
    [_ (crypto-error "signature is not well-formed")]))

;; ----------------------------------------
;; New DSA API (Nettle >= 3.0)

(define nettle-dsa-impl%
  (class nettle-pk-impl%
    (inherit-field spec factory)
    (inherit get-random-ctx)
    (super-new (spec 'dsa))

    (define/override (can-sign? pad dspec) (memq pad '(#f)))
    (define/override (has-params?) #t)

    (define/override (generate-params config)
      (check-config config config:dsa-paramgen "DSA parameter generation")
      (let ([nbits (config-ref config 'nbits 2048)]
            [qbits (config-ref config 'qbits 256)])
        (define params (-genparams nbits qbits))
        (new nettle-dsa-params% (impl this) (params params))))

    (define/override (generate-key config)
      (check-config config config:dsa-paramgen "DSA key generation")
      (let ([nbits (config-ref config 'nbits 2048)]
            [qbits (config-ref config 'qbits 256)])
        (define params (-genparams nbits qbits))
        (define pub (new-mpz))
        (define priv (new-mpz))
        (nettle_dsa_generate_keypair params pub priv (get-random-ctx))
        (new nettle-dsa-key% (impl this) (params params) (pub pub) (priv priv))))

    (define/private (-genparams nbits qbits)
      (define params (new-dsa_params))
      (or (nettle_dsa_generate_params params (get-random-ctx) nbits qbits)
          (crypto-error "failed to generate parameters"))
      params)
    ))

(define nettle-dsa-params%
  (class pk-params-base%
    (init-field params)
    (inherit-field impl)
    (super-new)

    (define/override (generate-key config)
      (check-config config '() "DSA key generation from parameters")
      (define pub (new-mpz))
      (define priv (new-mpz))
      (nettle_dsa_generate_keypair params pub priv (send impl get-random-ctx))
      (new nettle-dsa-key% (impl impl) (params params) (pub pub) (priv priv)))

    (define/override (-write-params fmt)
      (encode-params-dsa fmt
                         (mpz->integer (dsa_params_struct-p params))
                         (mpz->integer (dsa_params_struct-q params))
                         (mpz->integer (dsa_params_struct-g params))))
    ))

(define nettle-dsa-key%
  (class pk-key-base%
    (init-field params pub priv)
    (inherit-field impl)
    (super-new)

    (define/override (is-private?) (and priv #t))

    (define/override (get-public-key)
      (if priv (new nettle-dsa-key% (impl impl) (params params) (pub pub) (priv #f)) this))

    (define/override (-write-key fmt)
      (define p (mpz->integer (dsa_params_struct-p params)))
      (define q (mpz->integer (dsa_params_struct-q params)))
      (define g (mpz->integer (dsa_params_struct-g params)))
      (define y (mpz->integer pub))
      (cond [priv (let ([x (mpz->integer priv)]) (encode-priv-dsa fmt p q g y x))]
            [else (encode-pub-dsa fmt p q g y)]))

    (define/override (equal-to-key? other)
      (and (is-a? other nettle-dsa-key%)
           (mpz=? (dsa_params_struct-p params)
                  (dsa_params_struct-p (get-field params other)))
           (mpz=? (dsa_params_struct-q params)
                  (dsa_params_struct-q (get-field params other)))
           (mpz=? (dsa_params_struct-g params)
                  (dsa_params_struct-g (get-field params other)))
           (mpz=? pub (get-field pub other))))

    (define/override (-sign digest digest-spec pad)
      (define sig (new-dsa_signature))
      (or (nettle_dsa_sign params priv (send impl get-random-ctx) digest sig)
          (crypto-error "signing failed"))
      (dsa_signature->der sig))

    (define/override (-verify digest digest-spec pad sig-der)
      (define sig (der->dsa_signature sig-der))
      (nettle_dsa_verify params pub digest sig))
    ))

;; ============================================================

(define nettle-ec-impl%
  (class nettle-pk-impl%
    (inherit-field spec factory)
    (inherit get-random-ctx)
    (super-new (spec 'ec))

    (define/override (can-sign? pad dspec) (memq pad '(#f)))
    (define/override (has-params?) #t)

    (define/override (generate-params config)
      (check-config config config:ec-paramgen "EC parameter generation")
      (define curve-name0 (config-ref config 'curve))
      (define curve-name (if (string? curve-name0) (string->symbol curve-name0) curve-name0))
      (define ecc (curve-name->ecc curve-name))
      (unless ecc (crypto-error "named curve not found\n  curve: ~e" curve-name0))
      (new nettle-ec-params% (impl this) (ecc ecc)))

    (define/override (generate-key config)
      (define params (generate-params config))
      (send params generate-key '()))
    ))

(define nettle-ec-params%
  (class pk-params-base%
    (init-field ecc)
    (inherit-field impl)
    (super-new)

    (define/override (generate-key config)
      (check-config config '() "EC key generation from parameters")
      (define pub (new-ecc_point ecc))
      (define priv (new-ecc_scalar ecc))
      (nettle_ecdsa_generate_keypair pub priv (send impl get-random-ctx))
      (new nettle-ec-key% (impl impl) (pub pub) (priv priv)))

    (define/override (-write-params fmt)
      (encode-params-ec fmt (ecc->curve-oid ecc)))
    ))

(define nettle-ec-key%
  (class pk-key-base%
    (init-field pub priv)
    (inherit-field impl)
    (super-new)

    (define/override (is-private?) (and priv #t))

    (define/override (get-public-key)
      (if priv (new nettle-ec-key% (impl impl) (pub pub) (priv #f)) this))

    (define/override (-write-key fmt)
      (define ecc (ecc_point_struct-ecc pub))
      (define curve-oid (ecc->curve-oid ecc))
      (define mlen (ecc->mlen ecc))
      (define qB
        (let ([xz (new-mpz)] [yz (new-mpz)])
          (nettle_ecc_point_get pub xz yz)
          (ec-point->bytes mlen (mpz->integer xz) (mpz->integer yz))))
      (cond [priv
             (define dz (new-mpz))
             (nettle_ecc_scalar_get priv dz)
             (encode-priv-ec fmt curve-oid qB (mpz->integer dz))]
            [else
             (encode-pub-ec fmt curve-oid qB)]))

    (define/override (equal-to-key? other)
      (and (is-a? other nettle-ec-key%)
           (ecc_point=? pub (get-field pub other))))

    (define/override (-sign digest digest-spec pad)
      (define randctx (send impl get-random-ctx))
      (define sig (new-dsa_signature))
      (nettle_ecdsa_sign priv randctx digest sig)
      (dsa_signature->der sig))

    (define/override (-verify digest digest-spec pad sig-der)
      (define sig (der->dsa_signature sig-der))
      (nettle_ecdsa_verify pub digest sig))
    ))

(define (ecc_point=? a b)
  (and (ptr-equal? (ecc_point_struct-ecc a) (ecc_point_struct-ecc b))
       (let ([ax (new-mpz)] [ay (new-mpz)]
             [bx (new-mpz)] [by (new-mpz)])
         (nettle_ecc_point_get a ax ay)
         (nettle_ecc_point_get b bx by)
         (and (mpz=? ax bx)
              (mpz=? ay by)))))

(define (ecc_scalar=? a b)
  (and (ptr-equal? (ecc_scalar_struct-ecc a) (ecc_scalar_struct-ecc b))
       (let ([az (new-mpz)] [bz (new-mpz)])
         (nettle_ecc_scalar_get a az)
         (nettle_ecc_scalar_get b bz)
         (mpz=? az bz))))

(define (ecc->curve-name ecc)
  (for/first ([e (in-list nettle-curves)] #:when (ptr-equal? ecc (cadr e)))
    (car e)))

(define (ecc->curve-oid ecc)
  (define curve-name (ecc->curve-name ecc))
  (and curve-name (curve-name->oid curve-name)))

(define (ecc->mlen ecc)
  (define curve-name (ecc->curve-name ecc))
  (define (f n) (quotient (+ n 7) 8)) ;; = ceil(n/8)
  (case curve-name
    [(secp192r1) (f 192)]
    [(secp224r1) (f 224)]
    [(secp256r1) (f 256)]
    [(secp384r1) (f 384)]
    [(secp521r1) (f 521)]
    [else #f]))

(define (curve-name->ecc curve-name)
  (cond [(assq curve-name nettle-curves) => cadr] [else #f]))

(define (curve-oid->ecc curve-oid)
  (curve-name->ecc (curve-oid->name curve-oid)))
