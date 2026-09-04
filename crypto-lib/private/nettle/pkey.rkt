;; Copyright 2014-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         brandx
         ffi/unsafe
         asn1
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/pk-common.rkt"
         "../common/error.rkt"
         gmp gmp/unsafe
         "ffi.rkt")
(provide nettle-fetch-pk)

(define (nettle-fetch-pk factory info)
  (case ($get-spec info)
    [(rsa)
     (and rsa-ok? (nettle-rsa-impl info factory (make-yarrow)))]
    [(dsa)
     (and new-dsa-ok? (nettle-dsa-impl info factory (make-yarrow)))]
    [(ec)
     (and ec-ok? (nettle-ec-impl info factory (make-yarrow)))]
    [(eddsa)
     (and (or ed25519-ok? ed448-ok?)
          (nettle-eddsa-impl info factory))]
    [(ecx)
     (and (or x25519-ok? x448-ok?)
          (nettle-ecx-impl info factory))]
    [else #f]))

;; ============================================================

(define DSA-Sig-Val (SEQUENCE [r INTEGER] [s INTEGER]))

(define (new-mpz) (mpz))
(define (integer->mpz n) (mpz n))
(define (mpz->integer z) (mpz->number z))
(define (mpz->bin z len) (mpz->bytes z len #f #t))
(define (bin->mpz buf) (bytes->mpz buf #f #t))

;; ============================================================

(struct nettle-pk-impl-base pk-impl-base (yarrow))

(define (get-random-ctx pki)
  (define y (nettle-pk-impl-base-yarrow pki))
  (let ([fuel (yarrow-fuel y)])
    (set-yarrow-fuel! y (sub1 fuel))
    (unless (positive? fuel)
      (yarrow-refresh! y)))
  (yarrow-ctx y))

(struct yarrow (ctx [fuel #:mutable]))

(define (make-yarrow)
  (define ctx (malloc YARROW256_CTX_SIZE 'atomic-interior))
  (cpointer-push-tag! ctx yarrow256_ctx-tag)
  (nettle_yarrow256_init ctx 0 #f)
  (yarrow ctx 0))

;; Number of *requests* between reseeds. (Each request represents a variable
;; (potentially large) number of random bytes produced.)
(define YARROW-FUEL 100)

(define (yarrow-refresh! y)
  (define entropy (crypto-random-bytes YARROW256_SEED_FILE_SIZE))
  (nettle_yarrow256_seed (yarrow-ctx y) entropy)
  (set-yarrow-fuel! y YARROW-FUEL))

;; ============================================================

(struct nettle-rsa-impl nettle-pk-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %])
   (define-struct-abbrevs nettle-rsa-impl)

   (define (%pk-can-sign? self pad dspec)
     (case pad
       [(pkcs1-v1.5 #f) (and (memq dspec '(#f md5 sha1 sha256 sha512)) #t)]
       [(pss) (and (memq dspec '(#f sha256 sha384 sha512)) #t)]
       [else #f]))

   (define (%pk-can-encrypt? self pad)
     (and (memq pad '(pkcs1-v1.5 #f)) #t))

   (define (%pk-generate-key self config)
     (define-values (nbits e)
       (check/ref-config '(nbits e) config config:rsa-keygen #:in self))
     (let ([e (or e 65537)])
       (define pub (new-rsa_public_key))
       (define priv (new-rsa_private_key))
       (mpz_set_si (rsa_public_key_struct-e pub) e)
       (or (nettle_rsa_generate_keypair pub priv (get-random-ctx self) nbits 0)
           (crypto-error "RSA key generation failed" #:in self))
       (pk-key self (keypair #f pub priv) #t)))

   ;; ----

   (define (%pkk-write-key self pkk fmt)
     (match-define (keypair _ pub priv) (ctx-inner pkk))
     (define n (mpz->integer (rsa_public_key_struct-n pub)))
     (define e (mpz->integer (rsa_public_key_struct-e pub)))
     (cond [priv
            (encode-priv-rsa fmt n e
                             (mpz->integer (rsa_private_key_struct-d priv))
                             (mpz->integer (rsa_private_key_struct-p priv))
                             (mpz->integer (rsa_private_key_struct-q priv))
                             (mpz->integer (rsa_private_key_struct-a priv))
                             (mpz->integer (rsa_private_key_struct-b priv))
                             (mpz->integer (rsa_private_key_struct-c priv)))]
           [else (encode-pub-rsa fmt n e)]))

   (define (%pkk-security-bits self pkk)
     (define pub (keypair-pub (ctx-inner pkk)))
     (rsa-security-bits (* 8 (rsa_public_key_struct-size pub))))

   (define (get-nbytes pkk)
     (define pub (keypair-pub (ctx-inner pkk)))
     (mpz-bytes-length (rsa_public_key_struct-n pub) #f))

   (define (%pk-make-public-key self n e)
     (define pub (new-rsa_public_key))
     (mpz_set (rsa_public_key_struct-n pub) (integer->mpz n))
     (mpz_set (rsa_public_key_struct-e pub) (integer->mpz e))
     (unless (nettle_rsa_public_key_prepare pub)
       (crypto-error "bad public key" #:in self))
     (pk-key self (keypair #f pub #f) #f))

   (define (%pk-make-private-key self n e d p q dp dq qInv)
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
       (crypto-error "bad public key" #:in self))
     (unless (nettle_rsa_private_key_prepare priv)
       (crypto-error "bad private key" #:in self))
     (pk-key self (keypair #f pub priv) #t))

   ;; ----

   (define (%pkk-sign self pkk digest digest-spec pad)
     (match-define (keypair _ pub priv) (ctx-inner pkk))
     (define randctx (get-random-ctx self))
     (define sigz (new-mpz))
     (define signed-ok?
       (case pad
         [(pkcs1-v1.5 #f)
          (case digest-spec
            [(md5)    (nettle_rsa_md5_sign_digest_tr    pub priv randctx digest sigz)]
            [(sha1)   (nettle_rsa_sha1_sign_digest_tr   pub priv randctx digest sigz)]
            [(sha256) (nettle_rsa_sha256_sign_digest_tr pub priv randctx digest sigz)]
            [(sha512) (nettle_rsa_sha512_sign_digest_tr pub priv randctx digest sigz)]
            [else (internal-error "bad pkcs1 digest" #:in pkk)])]
         [(pss)
          (define saltlen (digest-spec-size digest-spec))
          (define salt (crypto-random-bytes saltlen))
          (case digest-spec
            [(sha256) (nettle_rsa_pss_sha256_sign_digest_tr pub priv randctx saltlen salt digest sigz)]
            [(sha384) (nettle_rsa_pss_sha384_sign_digest_tr pub priv randctx saltlen salt digest sigz)]
            [(sha512) (nettle_rsa_pss_sha512_sign_digest_tr pub priv randctx saltlen salt digest sigz)]
            [else (internal-error "bad pss digest" #:in pkk)])]
         [else (internal-error "bad pad: ~e" pad #:in pkk)]))
     (unless signed-ok? (crypto-error "signing failed" #:in pkk))
     (mpz->bin sigz (get-nbytes pkk)))

   (define (%pkk-verify self pkk digest digest-spec pad sig)
     (match-define (keypair _ pub priv) (ctx-inner pkk))
     (define sigz (bin->mpz sig))
     (define verified-ok?
       (case pad
         [(pkcs1-v1.5 #f)
          (case digest-spec
            [(md5)    (nettle_rsa_md5_verify_digest    pub digest sigz)]
            [(sha1)   (nettle_rsa_sha1_verify_digest   pub digest sigz)]
            [(sha256) (nettle_rsa_sha256_verify_digest pub digest sigz)]
            [(sha512) (nettle_rsa_sha512_verify_digest pub digest sigz)]
            [else (internal-error "bad pkcs1 digest" #:in pkk)])]
         [(pss)
          (define saltlen (digest-spec-size digest-spec))
          (case digest-spec
            [(sha256) (nettle_rsa_pss_sha256_verify_digest pub saltlen digest sigz)]
            [(sha384) (nettle_rsa_pss_sha384_verify_digest pub saltlen digest sigz)]
            [(sha512) (nettle_rsa_pss_sha512_verify_digest pub saltlen digest sigz)]
            [else (internal-error "bad pss digest" #:in pkk)])]
         [else (internal-error "bad pad: ~e" pad #:in pkk)]))
     verified-ok?)

   ;; ----

   (define (%pkk-encrypt self pkk data pad)
     (match-define (keypair _ pub _) (ctx-inner pkk))
     (case pad
       [(pkcs1-v1.5 #f)
        (define enc-z (new-mpz))
        (or (nettle_rsa_encrypt pub (get-random-ctx self) data enc-z)
            (crypto-error "encryption failed" #:in pkk))
        (mpz->bin enc-z (get-nbytes pkk))]
       [else (internal-error "bad pad: ~e" pad #:in pkk)]))

   (define (%pkk-decrypt self pkk data pad)
     (match-define (keypair _ pub priv) (ctx-inner pkk))
     (case pad
       [(pkcs1-v1.5 #f)
        (define randctx (get-random-ctx self))
        (define enc-z (bin->mpz data))
        (define dec-buf (make-bytes (rsa_public_key_struct-size pub)))
        (define dec-size (nettle_rsa_decrypt_tr pub priv randctx dec-buf enc-z))
        (unless dec-size (crypto-error "decryption failed" #:in pkk))
        (shrink-bytes dec-buf dec-size)]
       [else (internal-error "bad pad: ~e" pad #:in pkk)]))
   ))

;; ============================================================
;; DSA

(define (dsa_signature->der sig)
  (asn1->bytes/DER DSA-Sig-Val
    (hasheq 'r (mpz->integer (dsa_signature_struct-r sig))
            's (mpz->integer (dsa_signature_struct-s sig)))))

(define (der->dsa_signature der)
  (match (with-handlers ([exn:fail:asn1? void])
           (bytes->asn1/DER DSA-Sig-Val der))
    [(hash-table ['r (? exact-nonnegative-integer? r)]
                 ['s (? exact-nonnegative-integer? s)])
     (define sig (new-dsa_signature))
     (mpz_set (dsa_signature_struct-r sig) (integer->mpz r))
     (mpz_set (dsa_signature_struct-s sig) (integer->mpz s))
     sig]
    [_ #f]))

;; ----------------------------------------
;; New DSA API (Nettle >= 3.0)

(struct nettle-dsa-impl nettle-pk-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %])
   (define-struct-abbrevs nettle-dsa-impl)

   ;; ----

   (define (%pk-generate-params self config)
     (define-values (nbits qbits)
       (check/ref-config '(nbits qbits) config config:dsa-paramgen #:in self))
     (let ([qbits (or qbits 256)])
       (define params (new-dsa_params))
       (or (nettle_dsa_generate_params params (get-random-ctx) nbits qbits)
           (crypto-error "failed to generate parameters" #:in self))
       (pk-parameters self params)))

   ;; ----

   (define (%pkp-generate-key self pkp)
     (define params (ctx-inner pkp))
     (define pub (new-mpz))
     (define priv (new-mpz))
     (nettle_dsa_generate_keypair params pub priv (get-random-ctx self))
     (pk-key self (keypair params pub priv) #t))

   (define (%pkp-param-values self pkp)
     (define params (ctx-inner pkp))
     (values (mpz->integer (dsa_params_struct-p params))
             (mpz->integer (dsa_params_struct-q params))
             (mpz->integer (dsa_params_struct-g params))))

   ;; ----

   (define (%pkk-write-key self pkk fmt)
     (match-define (keypair params pub priv) (ctx-inner pkk))
     (define p (mpz->integer (dsa_params_struct-p params)))
     (define q (mpz->integer (dsa_params_struct-q params)))
     (define g (mpz->integer (dsa_params_struct-g params)))
     (define y (mpz->integer pub))
     (cond [priv (let ([x (mpz->integer priv)]) (encode-priv-dsa fmt p q g y x))]
           [else (encode-pub-dsa fmt p q g y)]))

   (define (%pkk-security-bits self pkk)
     (match-define (keypair params pub priv) (ctx-inner pkk))
     (dsa/dh-security-bits (mpz_sizeinbase (dsa_params_struct-p params) 2)
                           (mpz_sizeinbase (dsa_params_struct-q params) 2)))

   (define (%pk-make-params self p q g)
     (define params (make-params p q g))
     (pk-parameters self params))

   (define (%pk-make-public-key self p q g y)
     (define params (make-params p q g))
     (define pub (integer->mpz y))
     (pk-key self (keypair params pub #f) #f))

   (define (%pk-make-private-key self p q g y x)
     (define params (make-params p q g))
     (define priv (integer->mpz x))
     (define pub (integer->mpz y))
     (pk-key self (keypair params pub priv) #t))

   (define (make-params p q g)
     (define params (new-dsa_params))
     (mpz_set (dsa_params_struct-p params) (integer->mpz p))
     (mpz_set (dsa_params_struct-q params) (integer->mpz q))
     (mpz_set (dsa_params_struct-g params) (integer->mpz g))
     params)

   ;; ----

   (define (%pkk-sign self pkk digest digest-spec pad)
     (match-define (keypair params pub priv) (ctx-inner pkk))
     (define sig (new-dsa_signature))
     (or (nettle_dsa_sign params priv (get-random-ctx self) digest sig)
         (crypto-error "signing failed" #:in pkk))
     (dsa_signature->der sig))

   (define (%pkk-verify self pkk digest digest-spec pad sig-der)
     (match-define (keypair params pub priv) (ctx-inner pkk))
     (define sig (der->dsa_signature sig-der))
     (and sig (nettle_dsa_verify params pub digest sig)))
   ))

;; ============================================================
;; EC

;; On rejecting points not on curve as (untrusted) public keys:
;; nettle_ecc_point_set checks the point, indicates whether okay.

(struct nettle-ec-impl nettle-pk-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %])

   (define (%pk-generate-params self config)
     (check-config config config:ec-paramgen #:in self)
     (define curve (alias->curve-name (config-ref config 'curve)))
     (define ecc (curve-name->ecc curve))
     (unless ecc (err/no-curve (config-ref config 'curve) self))
     (pk-parameters self ecc))

   ;; ----

   (define (%pkp-generate-key self pkp)
     (define ecc (ctx-inner pkp))
     (define pub (new-ecc_point ecc))
     (define priv (new-ecc_scalar ecc))
     (nettle_ecdsa_generate_keypair pub priv (get-random-ctx self))
     (pk-key self (keypair ecc pub priv) #t))

   (define (%pkp-param-values self pkp)
     (define ecc (ctx-inner pkp))
     (ecc->curve-name ecc))

   ;; ----

   (define (%pkk-write-key self pkk fmt)
     (match-define (keypair ecc pub priv) (ctx-inner pkk))
     (define curve-oid (ecc->curve-oid ecc))
     (define mlen (ecc->mlen ecc))
     (define qB (ecc_point->bytes ecc pub))
     (cond [priv
            (define dz (new-mpz))
            (nettle_ecc_scalar_get priv dz)
            (encode-priv-ec fmt curve-oid qB (mpz->integer dz))]
           [else
            (encode-pub-ec fmt curve-oid qB)]))

   (define (%pk-make-params self curve-oid)
     (define ecc (curve-oid->ecc curve-oid))
     (pk-parameters self ecc))

   (define (%pk-make-public-key self curve-oid qB)
     (define ecc (curve-oid->ecc curve-oid))
     (cond [(and ecc (bytes->ec-point qB))
            => (lambda (x+y)
                 (define x (integer->mpz (car x+y)))
                 (define y (integer->mpz (cdr x+y)))
                 (define pub (new-ecc_point ecc))
                 (unless (nettle_ecc_point_set pub x y)
                   (err/off-curve "public key" #:in self))
                 (pk-key self (keypair ecc pub #f) #f))]
           [else #f]))

   (define (%pk-make-private-key self curve-oid qB d)
     (define ecc (curve-oid->ecc curve-oid))
     (cond [ecc
            (define priv (new-ecc_scalar ecc))
            (unless (nettle_ecc_scalar_set priv (integer->mpz d))
              (crypto-error "invalid private key" #:in self))
            (define pub (recompute-ec-q ecc priv))
            (when qB (check-recomputed-qB (ecc_point->bytes ecc pub) qB))
            (pk-key self (keypair ecc pub priv) #t)]
           [else #f]))

   (define (recompute-ec-q ecc priv)
     (define pub (new-ecc_point ecc))
     (nettle_ecc_point_mul_g pub priv)
     pub)

   ;; ----

   (define (%pkk-sign self pkk digest digest-spec pad)
     (match-define (keypair ecc pub priv) (ctx-inner pkk))
     (define randctx (get-random-ctx self))
     (define sig (new-dsa_signature))
     (nettle_ecdsa_sign priv randctx digest sig)
     (dsa_signature->der sig))

   (define (%pkk-verify self pkk digest digest-spec pad sig-der)
     (match-define (keypair ecc pub priv) (ctx-inner pkk))
     (define sig (der->dsa_signature sig-der))
     (and sig (nettle_ecdsa_verify pub digest sig)))

   ;; ----

   (define (%pkk-compute-secret self pkk peer-pubkey)
     (match-define (keypair ecc pub priv) (ctx-inner pkk))
     (define peer-ecp (keypair-pub (ctx-inner peer-pubkey)))
     (define shared-ecp (new-ecc_point ecc))
     (nettle_ecc_point_mul shared-ecp priv peer-ecp)
     (define x (mpz))
     (define y (mpz))
     (nettle_ecc_point_get shared-ecp x y)
     (define ecc-size (ceil/ (nettle_ecc_bit_size ecc) 8))
     (mpz->bytes x ecc-size #f #t))

   (define (%pkk-import-for-key-agree self pkk bs)
     (match-define (keypair ecc pub priv) (ctx-inner pkk))
     (define curve-oid (ecc->curve-oid ecc))
     ($pk-make-public-key self curve-oid bs))
   ))

(define (ecc_point=? a b)
  (and (ptr-equal? (ecc_point_struct-ecc a) (ecc_point_struct-ecc b))
       (let ([ax (new-mpz)] [ay (new-mpz)]
             [bx (new-mpz)] [by (new-mpz)])
         (nettle_ecc_point_get a ax ay)
         (nettle_ecc_point_get b bx by)
         (and (mpz=? ax bx)
              (mpz=? ay by)))))

(define (ecc_point->bytes ecc pub)
  (let ([xz (new-mpz)] [yz (new-mpz)])
    (nettle_ecc_point_get pub xz yz)
    (ec-point->bytes (ecc->mlen ecc) (mpz->integer xz) (mpz->integer yz))))

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
  (ceil/ (nettle_ecc_bit_size ecc) 8))

(define (curve-name->ecc curve-name)
  (cond [(assq curve-name nettle-curves) => cadr] [else #f]))

(define (curve-oid->ecc curve-oid)
  (curve-name->ecc (curve-oid->name curve-oid)))

;; ============================================================
;; Ed25519 and Ed448

(struct nettle-eddsa-impl eddsa-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %]
             [curve-ok$ #:prefix %])
   (define-struct-abbrevs nettle-eddsa-impl)

   (define (%curve-ok? self curve)
     (match curve
       ['ed25519 ed25519-ok?]
       ['ed448 ed448-ok?]
       [_ #f]))

   ;; ----

   (define (%pkp-generate-key self pkp)
     (case (ctx-inner pkp)
       [(ed25519) (and ed25519-ok? (generate-ed25519-key self))]
       [(ed448) (and ed448-ok? (generate-ed448-key self))]))

   (define (generate-ed25519-key self)
     (define priv (crypto-random-bytes ED25519_KEY_SIZE))
     (define pub (make-bytes ED25519_KEY_SIZE))
     (nettle_ed25519_sha512_public_key pub priv)
     (pk-key self (keypair 'ed25519 pub priv) #t))

   (define (generate-ed448-key self)
     (define priv (crypto-random-bytes ED448_KEY_SIZE))
     (define pub (make-bytes ED448_KEY_SIZE))
     (nettle_ed448_shake256_public_key pub priv)
     (pk-key self (keypair 'ed448 pub priv) #t))

   (define (%pk-make-private-key self curve qB dB)
     ;; public key might be missing, so recompute; if present, check
     (define (make-ed25519-private-key)
       (define priv (eddsa-check-keys curve #t dB qB))
       (define pub (make-bytes ED25519_KEY_SIZE))
       (nettle_ed25519_sha512_public_key pub priv)
       (check-recomputed-qB pub qB)
       (pk-key self (keypair curve pub priv) #t))
     (define (make-ed448-private-key)
       (define priv (eddsa-check-keys curve #t dB qB))
       (define pub (make-bytes ED448_KEY_SIZE))
       (nettle_ed448_shake256_public_key pub priv)
       (check-recomputed-qB pub qB)
       (pk-key self (keypair curve pub priv) #t))
     (case curve
       [(ed25519) (and ed25519-ok? (make-ed25519-private-key))]
       [(ed448) (and ed448-ok? (make-ed448-private-key))]
       [else #f]))

   ;; ----

   (define (%pkk-sign self pkk msg _dspec _pad)
     (match-define (keypair curve pub priv) (ctx-inner pkk))
     (match curve
       ['ed25519
        (define sig (make-bytes ED25519_SIGNATURE_SIZE))
        (nettle_ed25519_sha512_sign pub priv (bytes-length msg) msg sig)
        sig]
       ['ed448
        (define sig (make-bytes ED448_SIGNATURE_SIZE))
        (nettle_ed448_shake256_sign pub priv (bytes-length msg) msg sig)
        sig]))

   (define (%pkk-verify self pkk msg _dspec _pad sig)
     (match-define (keypair curve pub _) (ctx-inner pkk))
     (match curve
       ['ed25519
        (and (= (bytes-length sig) ED25519_SIGNATURE_SIZE)
             (nettle_ed25519_sha512_verify pub (bytes-length msg) msg sig))]
       ['ed448
        (and (= (bytes-length sig) ED448_SIGNATURE_SIZE)
             (nettle_ed448_shake256_verify pub (bytes-length msg) msg sig))]
       [else (internal-error "bad curve: ~e" curve #:in pkk)]))
   ))

;; ============================================================
;; X25519 and X448

(struct nettle-ecx-impl ecx-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %]
             [curve-ok$ #:prefix %])

   (define (%curve-ok? self curve)
     (match curve
       ['x25519 x25519-ok?]
       ['x448 x448-ok?]
       [else #f]))

   ;; ----

   (define (%pkp-generate-key self pkp)
     (define curve ($pkp-param-values self pkp))
     (case curve
       [(x25519)
        (define priv (crypto-random-bytes X25519_KEY_SIZE))
        (ecx-clamp-secret! 'x25519 priv)
        (define pub (make-bytes X25519_KEY_SIZE))
        (nettle_curve25519_mul_g pub priv)
        (pk-key self (keypair curve pub priv) #t)]
       [(x448)
        (define priv (crypto-random-bytes X448_KEY_SIZE))
        (ecx-clamp-secret! 'x448 priv)
        (define pub (make-bytes X448_KEY_SIZE))
        (nettle_curve448_mul_g pub priv)
        (pk-key self (keypair curve pub priv) #t)]
       [else (internal-error "bad curve: ~e" curve #:in pkp)]))

   (define (%pk-make-private-key self curve qB dB)
     (cond [($curve-ok? self curve)
            (case curve
              [(x25519)
               (define priv (ecx-check-keys curve #t dB qB))
               (define pub (make-bytes X25519_KEY_SIZE))
               (nettle_curve25519_mul_g pub priv)
               (check-recomputed-qB pub qB)
               (pk-key self (keypair curve pub priv) #t)]
              [(x448)
               (define priv (ecx-check-keys curve #t dB qB))
               (define pub (make-bytes X448_KEY_SIZE))
               (nettle_curve448_mul_g pub priv)
               (check-recomputed-qB pub qB)
               (pk-key self (keypair curve pub priv) #t)])]
           [else #f]))

   ;; ----

   (define (%pkk-compute-secret self pkk peer-pubkey)
     (match-define (keypair curve pub priv) (ctx-inner pkk))
     (define peer (keypair-pub (ctx-inner peer-pubkey)))
     (case curve
       [(x25519)
        (define secret (make-bytes X25519_KEY_SIZE))
        (nettle_curve25519_mul secret priv peer)
        secret]
       [(x448)
        (define secret (make-bytes X448_KEY_SIZE))
        (nettle_curve448_mul secret priv peer)
        secret]))

   (define (%pkk-import-for-key-agree self pkk bs)
     (define curve (keypair-param (ctx-inner pkk)))
     ($pk-make-public-key self curve bs))
   ))
