;; Copyright 2013-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         ffi/unsafe
         scramble/bundle
         scramble/struct
         asn1
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/pk-common.rkt"
         "../common/error.rkt"
         "../common/base256.rkt"
         "ffi.rkt")
(provide gcrypt-fetch-pk)

(define (gcrypt-fetch-pk factory info)
  (define spec ($get-spec info))
  (case spec
    [(rsa) (gcrypt-rsa-impl info factory)]
    [(dsa) (gcrypt-dsa-impl info factory)]
    [(ec)  (gcrypt-ec-impl info factory)]
    [(eddsa) (and ed25519-ok? (gcrypt-eddsa-impl info factory))]
    [(ecx) (and x25519-ok? (gcrypt-ecx-impl info factory))]
    [else #f]))

;; ============================================================

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
(define (sexp-get-ints outersexp outertag tags)
  (for/list ([tag (in-list tags)])
    (mpi->int (sexp-get-mpi outersexp outertag tag))))

;; ============================================================

(struct gcrypt-pk-impl-base pk-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %]
             [pk*$ #:prefix %])
   #:import ([pk-impl$ #:super #:prefix super-])

   (define (%pkk-public-key self pkk)
     (match-define (pk-key impl (keypair param pub priv) private?) pkk)
     (if private? (pk-key impl (keypair param pub #f) #f) pkk))

   (define (%pkk-params self pkk)
     (cond [($pk-has-params? self)
            (define param (keypair-param (ctx-inner pkk)))
            (pk-parameters self param)]
           [else (super-pkk-params self pkk)]))
   ))

;; ----------------------------------------

(define (generate-keypair keygen-sexp)
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

(define (gcrypt-sign* pkk data-sexp sign-unpack-sig-sexp)
  (match-define (keypair _ pub priv) (ctx-inner pkk))
  (define sig-sexp (gcry_pk_sign data-sexp priv))
  (begin0 (and sig-sexp (sign-unpack-sig-sexp sig-sexp))
    (when sig-sexp (gcry_sexp_release sig-sexp))
    (gcry_sexp_release data-sexp)))

(define (gcrypt-verify* pkk data-sexp sig-sexp)
  (match-define (keypair _ pub priv) (ctx-inner pkk))
  (define sig-sexp (gcry_pk_sign data-sexp priv))
  (begin0 (gcry_pk_verify sig-sexp data-sexp pub)
    (gcry_sexp_release sig-sexp)
    (gcry_sexp_release data-sexp)))

(define (dsa/ecdsa-make-data-sexp digest digest-spec pad pkk)
  (when pad (internal-error "bad signature pad: ~e" pad))
  ;; When the digest is larger than the bits of the EC field, it must be
  ;; truncated, but gcrypt cannot truncate externally-created digest.
  ;; (See comment before _gcry_dsa_normalize_hash in libgcrypt source.)
  (define qbits
    (let ([pub (keypair-pub (ctx-inner pkk))])
      (gcry_pk_get_nbits pub)))
  (define digest* (if (> (* 8 (bytes-length digest)) qbits)
                      (subbytes digest 0 (quotient (+ qbits 7) 8))
                      digest))
  (make-sexp `(data (flags raw) (value ,digest*))))

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

(define (dsa/ecdsa-make-sig-sexp sig-der)
  (match (with-handlers ([exn:fail:asn1? void])
           (bytes->asn1/DER DSA-Sig-Val sig-der))
    [(hash-table ['r (? exact-nonnegative-integer? r)]
                 ['s (? exact-nonnegative-integer? s)])
     (make-sexp `(sig-val (ecdsa (r ,(unsigned->base256 r))
                                 (s ,(unsigned->base256 s)))))]
    [_ #f]))

#;
(define gcrypt-pk-key%
  (class pk-key-base%
    (init-field pub priv)
    (inherit-field impl)
    (super-new)

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
      (define result (and sig-sexp (gcry_pk_verify sig-sexp data-sexp pub)))
      (when sig-sexp (gcry_sexp_release sig-sexp))
      (gcry_sexp_release data-sexp)
      result)

    (abstract sign-make-data-sexp
              sign-unpack-sig-sexp
              verify-make-sig-sexp
              check-sig-pad)
    ))

(struct keypair (param pub priv))

;; ============================================================

(struct gcrypt-rsa-impl gcrypt-pk-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %]
             [pk*$ #:prefix %])
   (define-struct-abbrevs gcrypt-rsa-impl)

   (define (%pk-can-sign? self pad dspec)
     (and (memq pad '(#f pkcs1-v1.5 pss))
          ;; Sign/verify fails on some digests (eg, blake2*, sha512/256), not clear
          ;; how to pre-check (gcry_md_get_asnoid not helpful).
          (cond [(memq dspec '(#f)) #t]
                [(memq dspec '(sha1 sha224 sha256 sha384 md5))
                 (and ($fetch-digest (.factory self) dspec) #t)]
                [(memq dspec '(sha512 sha3-224 sha3-256 sha3-384 sha3-512))
                 ;; Unavailable or broken for signing in earlier versions (1.9.4).
                 (and v1.11/later? ($fetch-digest (.factory self) dspec) #t)]
                [else #f])))

   (define (%pk-can-encrypt? self pad)
     (and (memq pad '(#f pkcs1-v1.5 oaep)) #t))

   (define (%pk-generate-key self config)
     (define-values (nbits e)
       (check/ref-config '(nbits e) config config:rsa-keygen #:in self))
     (let (;; e default 0 means use gcrypt default "secure and fast value"
           [e (or e 0)])
       (define-values (pub priv)
         (generate-keypair (make-sexp `(genkey (rsa (nbits ,nbits) (rsa-use-e ,e))))))
       (pk-key self (keypair #f pub priv) #t)))

   ;; ----

   (define (%pkk-write-key self pkk fmt)
     (match-define (keypair _ pub priv) (ctx-inner pkk))
     (cond [priv
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
                (internal-error "failed to calculate dP" #:in pkk))
            (define dq-mpi (gcry_mpi_new))
            (gcry_mpi_sub_ui tmp q-mpi 1)
            (or (gcry_mpi_invm dq-mpi e-mpi tmp)
                (internal-error "failed to calculate dQ" #:in pkk))
            (define qInv-mpi (gcry_mpi_new))
            (or (gcry_mpi_invm qInv-mpi p-mpi q-mpi)
                (internal-error "failed to calculate qInv" #:in pkk))
            (apply encode-priv-rsa fmt
                   (map mpi->int
                        (list n-mpi e-mpi d-mpi p-mpi q-mpi dp-mpi dq-mpi qInv-mpi)))]
           [else
            (define (get-mpi tag) (sexp-get-mpi pub "rsa" tag))
            (define n-mpi (get-mpi "n"))
            (define e-mpi (get-mpi "e"))
            (encode-pub-rsa fmt (mpi->int n-mpi) (mpi->int e-mpi))]))

   (define (%pkk-security-bits self pkk)
     (rsa-security-bits (gcry_pk_get_nbits (keypair-pub (ctx-inner pkk)))))

   ;; ---- pk*

   (define (%pk*-make-public-key self n e)
     (define pub (make-rsa-public-key n e))
     (pk-key self (keypair #f pub #f) #f))

   (define (%pk*-make-private-key self n e d p0 q0 dp dq qInv)
     ;; gcrypt requires p < q; simpler to just always recompute u
     (define-values (p q) (if (< p0 q0) (values p0 q0) (values q0 p0)))
     (define u-mpi (gcry_mpi_new))
     (unless (gcry_mpi_invm u-mpi (int->mpi p) (int->mpi q))
       (internal-error "failed to calculate qInv" #:in self))
     (define u (mpi->int u-mpi))
     (define pub (make-rsa-public-key n e))
     (define priv (make-rsa-private-key n e d p q u))
     (pk-key self (keypair #f pub priv) #t))

   (define (make-rsa-public-key n e)
     (make-sexp `(public-key (rsa (n ,(unsigned->base256 n))
                                  (e ,(unsigned->base256 e))))))

   (define (make-rsa-private-key n e d p q u)
     (define priv
       (make-sexp `(private-key (rsa (n ,(unsigned->base256 n))
                                     (e ,(unsigned->base256 e))
                                     (d ,(unsigned->base256 d))
                                     (p ,(unsigned->base256 p))
                                     (q ,(unsigned->base256 q))
                                     (u ,(unsigned->base256 u))))))
     (gcry_pk_testkey priv)
     priv)

   ;; ----

   (define (%pkk*-sign self pkk digest digest-spec pad)
     (define data-sexp (sign-make-data-sexp digest digest-spec pad))
     (gcrypt-sign* pkk sign-unpack-sig-sexp))

   (define (%pkk*-verify self pkk digest digest-spec pad sig)
     (define data-sexp (sign-make-data-sexp digest digest-spec pad))
     (define sig-sexp (verify-make-sig-sexp sig))
     (gcrypt-verify* pkk data-sexp sig-sexp))

   (define (sign-make-data-sexp digest digest-spec pad)
     (define padding (check-sig-pad pad))
     (case pad
       [(pss)
        (make-sexp `(data (flags pss)
                          (salt-length ,(digest-spec-size digest-spec))
                          (hash ,digest-spec ,digest)))]
       [else
        (make-sexp `(data (flags ,padding)
                          (hash ,digest-spec ,digest)))]))

   (define (sign-unpack-sig-sexp sig-sexp)
     (define sig-part (gcry_sexp_find_token sig-sexp "rsa"))
     (define sig-s-part (gcry_sexp_find_token sig-part "s"))
     (define sig-data (gcry_sexp_nth_data sig-s-part 1))
     (gcry_sexp_release sig-s-part)
     (gcry_sexp_release sig-part)
     sig-data)

   (define (check-sig-pad pad)
     (case pad
       [(pss) #"pss"]
       [(pkcs1-v1.5 #f) #"pkcs1"]
       [else (internal-error "bad padding: ~e" pad)]))

   (define (verify-make-sig-sexp sig)
     (make-sexp `(sig-val (rsa (s ,sig)))))

   ;; ----

   (define (%pkk*-encrypt self pkk data pad)
     (match-define (keypair _ pub _) (ctx-inner pkk))
     (when (zero? (bytes-length data))
       ;; gcrypt cannot encrypt the empty message, because
       ;; it does notallow empty octet strings in sexps
       (crypto-error "encryption failed (empty message)" #:in pkk))
     (define padding (check-enc-padding pad))
     (define data-sexp (make-sexp `(data (flags ,padding) (value ,data))))
     (define enc-sexp (gcry_pk_encrypt data-sexp pub))
     (define enc-part (gcry_sexp_find_token enc-sexp "rsa"))
     (define enc-a-part (gcry_sexp_find_token enc-part "a"))
     (define enc-mpi (gcry_sexp_nth_mpi enc-a-part 1))
     (begin0 (mpi->base256 enc-mpi)
       (gcry_mpi_release enc-mpi)
       (gcry_sexp_release enc-a-part)
       (gcry_sexp_release enc-part)
       (gcry_sexp_release enc-sexp)
       (gcry_sexp_release data-sexp)))

   (define (%pkk*-decrypt self pkk data pad)
     (match-define (keypair _ _ priv) (ctx-inner pkk))
     (define padding (check-enc-padding pad))
     (define enc-sexp (make-sexp `(enc-val (flags ,padding) (rsa (a ,data)))))
     (define dec-sexp (or (gcry_pk_decrypt enc-sexp priv)
                          (crypto-error "decryption failed" #:in pkk)))
     (begin0 (gcry_sexp_nth_data dec-sexp 1)
       (gcry_sexp_release enc-sexp)
       (gcry_sexp_release dec-sexp)))

   (define (check-enc-padding pad)
     (case pad
       [(#f oaep) #"oaep"]
       [(pkcs1-v1.5) #"pkcs1"]
       [else (internal-error "bad padding: ~e" pad)]))
   ))

;; ============================================================

(struct gcrypt-dsa-impl gcrypt-pk-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %]
             [pk*$ #:prefix %])
   (define-struct-abbrevs gcrypt-dsa-impl)

   ;; ----

   (define (%pk-generate-params self config)
     ;; gcrypt has no separate paramgen operation,
     ;; so generate private key and extract params
     (define pkk (generate-key config self))
     (match ($pkk-write-key self pkk 'rkt-params)
       [(list 'rkt 'params p q g) ($pk*-make-params p q g)]))

   (define (generate-key config [inval #f])
     (define-values (nbits qbits)
       (check/ref-config '(nbits qbits) config config:dsa-paramgen #:in inval))
     (let ([qbits (or qbits 256)])
       (define-values (pub priv)
         (generate-keypair
          (make-sexp `(genkey (dsa (nbits ,nbits) (qbits ,qbits))))))
       (define param (sexp-get-ints pub "dsa" '("p" "q" "g")))
       (keypair param pub priv)))

   ;; ----

   (define (%pkp-generate-key self pkp)
     (define-values (p q g) ($pkp-param-values self pkp))
     (define-values (pub priv)
       (generate-keypair
        (let ([p (unsigned->base256 p)]
              [q (unsigned->base256 q)]
              [g (unsigned->base256 g)])
          (make-sexp `(genkey (dsa (domain (p ,p) (q ,q) (g ,g))))))))
     (pk-key self (keypair (list p q g) pub priv) #t))

   (define (%pkp-param-values self pkp)
     (match-define (list p q g) (ctx-inner pkp))
     (values p q g))

   ;; ----

   (define (%pkk-write-key self pkk fmt)
     (match-define (keypair #f pub priv) (ctx-inner pkk))
     (cond [priv
            (define vs (sexp-get-ints priv "dsa" '("p" "q" "g" "y" "x")))
            (apply encode-priv-dsa fmt vs)]
           [else
            (define vs (sexp-get-ints pub "dsa" '("p" "q" "g" "y")))
            (apply encode-pub-dsa fmt vs)]))

   (define (%pkk-security-bits self pkk)
     (dsa/dh-security-bits (gcry_pk_get_nbits (keypair-pub (ctx-inner pkk)))))

   ;; ---- pk*

   (define (%pk*-make-params self p q g)
     (pk-parameters self (list p q g)))

   (define (%pk*-make-public-key self p q g y)
     (define pub (make-dsa-public-key p q g y))
     (pk-key self (keypair (list p q g) pub #f) #f))

   (define (%pk*-make-private-key self p q g y x)
     (define pub (make-dsa-public-key p q g y))
     (define priv (make-dsa-private-key p q g y x))
     (pk-key self (keypair (list p q g) pub priv) #t))

   (define (make-dsa-public-key p q g y)
     (make-sexp `(public-key (dsa (p ,(unsigned->base256 p))
                                  (q ,(unsigned->base256 q))
                                  (g ,(unsigned->base256 g))
                                  (y ,(unsigned->base256 y))))))

   (define (make-dsa-private-key p q g y x)
     (define priv
       (make-sexp `(private-key (dsa (p ,(unsigned->base256 p))
                                     (q ,(unsigned->base256 q))
                                     (g ,(unsigned->base256 g))
                                     (y ,(unsigned->base256 y))
                                     (x ,(unsigned->base256 x))))))
     (gcry_pk_testkey priv)
     priv)

   ;; ----

   (define (%pkk*-sign self pkk digest digest-spec pad)
     (define data-sexp (dsa/ecdsa-make-data-sexp digest digest-spec pad pkk))
     (gcrypt-sign* pkk sign-unpack-sig-sexp))

   (define (%pkk*-verify self pkk digest digest-spec pad sig)
     (define data-sexp (dsa/ecdsa-make-data-sexp digest digest-spec pad pkk))
     (define sig-sexp (dsa/ecdsa-make-sig-sexp sig))
     (gcrypt-verify* pkk data-sexp sig-sexp))

   (define (sign-unpack-sig-sexp sig-sexp)
     (unpack-sig-sexp sig-sexp "dsa"))
   ))

;; ============================================================

(struct gcrypt-ec-impl gcrypt-pk-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %]
             [pk*$ #:prefix %])

   (define (%pk-generate-params self config)
     (check-config config config:ec-paramgen #:in self)
     (define curve (config-ref config 'curve))
     (curve->params self curve))

   (define (curve->params self curve)
     (define curve* (alias->curve-name curve))
     (unless (memq curve* gcrypt-curves)
       (err/no-curve curve self))
     (pk-parameters self curve*))

   ;; ----

   (define (%pkp-generate-key self pkp)
     (define curve ($pkp-param-values self pkp))
     (define-values (pub priv)
       (generate-keypair
        (make-sexp `(genkey (ecc (curve ,curve))))))
     (pk-key self (keypair curve pub priv) #t))

   (define (%pkp-param-values self pkp)
     (ctx-inner pkp))

   ;; ----

   (define (%pkk-write-key self pkk fmt)
     (match-define (keypair _ pub priv) (ctx-inner pkk))
     (cond [priv
            (define curve-oid (sexp-get-curve-oid priv))
            (define qB (sexp-get-data priv "ecc" "q"))
            (define d (sexp-get-int priv "ecc" "d"))
            (and curve-oid (encode-priv-ec fmt curve-oid qB d))]
           [else
            (define curve-oid (sexp-get-curve-oid pub))
            (define qB (sexp-get-data pub "ecc" "q"))
            (and curve-oid (encode-pub-ec fmt curve-oid qB))]))

   (define (sexp-get-curve-oid sexp)
     (curve-alias->oid (sexp-get-curve sexp)))

   (define (sexp-get-curve sexp)
     (string->symbol (bytes->string/utf-8 (sexp-get-data sexp "ecc" "curve"))))

   ;; ---- pk*

   (define (%pk*-make-params self curve-oid)
     (curve->params self (curve-oid->name curve-oid)))

   (define (%pk*-make-public-key self curve-oid qB)
     (define curve (curve-oid->name curve-oid))
     (cond [(curve->name-string curve)
            => (lambda (curve-name)
                 (check-ec-q self curve-name qB)
                 (define pub (make-ec-public-key curve-name qB))
                 (pk-key self (keypair curve pub #f) #f))]
           [else #f]))

   (define (%pk*-make-private-key self curve-oid qB d)
     (define curve (curve-oid->name curve-oid))
     (cond [(curve->name-string curve)
            => (lambda (curve-name)
                 (define qB* (recompute-ec-q curve-name d))
                 (when qB (check-recomputed-qB qB* qB))
                 (define pub (make-ec-public-key curve-name qB*))
                 (define priv (make-ec-private-key curve-name qB* d))
                 (pk-key self (keypair curve pub priv) #t))]
           [else #f]))

   (define (make-ec-public-key curve qB)
     (make-sexp `(public-key (ecc (curve ,curve) (q ,qB)))))

   (define (make-ec-private-key curve qB d)
     (define priv
       (make-sexp `(private-key (ecc (curve ,curve)
                                     (q ,qB)
                                     (d ,(unsigned->base256 d))))))
     (gcry_pk_testkey priv)
     priv)

   (define (check-ec-q self curve-name qB)
     (when decode-point-ok?
       (define ec (gcry_mpi_ec_new curve-name))
       (define qpoint (gcry_mpi_point_new))
       (gcry_mpi_ec_decode_point qpoint (base256->mpi qB) ec)
       (begin0 (unless (gcry_mpi_ec_curve_point qpoint ec)
                 (err/off-curve "public key" #:in self))
         (gcry_ctx_release ec)
         (gcry_mpi_point_release qpoint))))

   (define (recompute-ec-q curve-name d)
     (define ec (gcry_mpi_ec_new curve-name))
     (gcry_mpi_ec_set_mpi 'd (int->mpi d) ec)
     (define pub-sexp (gcry_pubkey_get_sexp GCRY_PK_GET_PUBKEY ec))
     (begin0 (sexp-get-data pub-sexp "ecc" "q")
       (gcry_sexp_release pub-sexp)
       (gcry_ctx_release ec)))

   (define (curve->name-string curve)
     (and (memq curve gcrypt-curves)
          (string->bytes/latin-1 (symbol->string curve))))

   ;; ----

   (define (%pkk*-sign self pkk digest digest-spec pad)
     (define data-sexp (dsa/ecdsa-make-data-sexp digest digest-spec pad pkk))
     (gcrypt-sign* pkk sign-unpack-sig-sexp))

   (define (%pkk*-verify self pkk digest digest-spec pad sig)
     (define data-sexp (dsa/ecdsa-make-data-sexp digest digest-spec pad pkk))
     (define sig-sexp (dsa/ecdsa-make-sig-sexp sig))
     (gcrypt-verify* pkk data-sexp sig-sexp))

   (define (sign-unpack-sig-sexp sig-sexp)
     (unpack-sig-sexp sig-sexp "ecdsa"))

   ;; ----

   ;; ECDH support is not documented, but described in comments in
   ;; libgcrypt/cipher/ecc.c before ecc_{encrypt,decrypt}_raw.
   (define (%pkk*-compute-secret self pkk peer-pubkey)
     (match-define (keypair _ pub priv) (ctx-inner pkk))
     (define peer (sexp-get-data (keypair-pub (ctx-inner peer-pubkey)) "ecc" "q"))
     (define dh-sexp (make-sexp `(enc-val (ecdh (e ,peer)))))
     (define sh (gcry_pk_decrypt dh-sexp priv))
     (define shb (gcry_sexp_nth_data sh 1))
     ;; shb is an EC point; decode and extract the x-coordinate
     ;; cf (unsigned->base256 (car (bytes->ec-point shb)))
     (define shblen (bytes-length shb))
     (subbytes shb 1 (+ 1 (quotient shblen 2))))

   (define (%pkk*-import-for-key-agree self pkk bs)
     (define curve-oid (sexp-get-curve-oid (keypair-pub (ctx-inner pkk))))
     ($pk*-make-public-key self curve-oid bs))
   ))

;; ============================================================

(struct gcrypt-eddsa-impl gcrypt-pk-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %]
             [pk*$ #:prefix %])
   (define-struct-abbrevs gcrypt-eddsa-impl)

   (define (%pk-generate-params self config)
     (check-config config config:eddsa-keygen #:in self)
     (curve->params self (config-ref config 'curve)))

   (define (curve->params self curve)
     (unless (check-curve curve) (err/no-curve curve self))
     (pk-parameters self curve))

   (define (check-curve curve)
     (case curve
       [(ed25519) (and ed25519-ok? "Ed25519")]
       [(ed448) (and ed448-ok? "Ed448")]
       [else #f]))

   ;; ----

   (define (%pkp-generate-key self pkp)
     (define curve ($pkp-param-values self pkp))
     (define curve-name (check-curve curve))
     (define-values (pub priv)
       (generate-keypair
        (make-sexp `(genkey (ecc (curve ,curve-name) (flags eddsa))))))
     (pk-key self (keypair curve pub priv) #t))

   (define (%pkp-param-values self pkp)
     (define curve-name (ctx-inner pkp))
     curve-name)

   ;; ----

   (define (%pkk-write-key self pkk fmt)
     (match-define (keypair curve pub priv) (ctx-inner pkk))
     (cond [priv
            (let ([qB (sexp-get-data priv "ecc" "q")]
                  [dB (sexp-get-data priv "ecc" "d")])
              (encode-priv-eddsa fmt curve qB dB))]
           [else
            (let ([qB (sexp-get-data pub "ecc" "q")])
              (encode-pub-eddsa fmt curve qB))]))

   ;; ---- pk*

   (define (%pk*-make-params self curve)
     (and (check-curve self curve) (curve->params curve)))

   (define (%pk*-make-public-key self curve qB)
     (define curve-name (check-curve curve))
     (define pub (make-public-sexp curve-name qB))
     (and curve-name (pk-key self (keypair curve pub #f) #f)))

   (define (%pk*-make-private-key self curve qB dB)
     (define curve-name (check-curve curve))
     ;; It doesn't seem to be possible to recover qB if missing, so just fail.
     (and curve-name qB
          (let ([pub (make-public-sexp curve-name qB)]
                [priv (make-private-sexp curve-name qB dB)])
            (pk-key self (keypair curve pub priv) #t))))

   (define (make-public-sexp curve-name qB)
     (make-sexp `(public-key (ecc (curve ,curve-name) (flags eddsa) (q ,qB)))))

   (define (make-private-sexp curve-name qB dB)
     (define priv
       (make-sexp `(private-key (ecc (curve ,curve-name)
                                     (flags eddsa)
                                     (q ,qB)
                                     (d ,dB)))))
     (gcry_pk_testkey priv)
     priv)

   ;; ----

   (define (%pkk*-sign self pkk digest digest-spec pad)
     (define curve (keypair-param (ctx-inner pkk)))
     (define data-sexp (sign-make-data-sexp digest digest-spec pad))
     (gcrypt-sign* pkk (make-sign-unpack-sig-sexp curve)))

   (define (%pkk*-verify self pkk digest digest-spec pad sig)
     (define curve (keypair-param (ctx-inner pkk)))
     (define data-sexp (sign-make-data-sexp digest digest-spec pad))
     (define sig-sexp (verify-make-sig-sexp sig curve))
     (gcrypt-verify* pkk data-sexp sig-sexp))

   (define (sign-make-data-sexp msg _dspec pad)
     (when pad (internal-error "bad signature pad: ~e" pad))
     ;; No (hash-algo sha512); wrong for Ed448, unnecessary for Ed25519 (tested 1.9.4).
     (make-sexp `(data (flags eddsa) (value ,msg))))

   (define ((make-sign-unpack-sig-sexp curve) sig-sexp)
     (define PARTLEN (case curve [(ed25519) 32] [(ed448) 57]))
     (define sig-part (gcry_sexp_find_token sig-sexp "eddsa"))
     (define sig-r-part (gcry_sexp_find_token sig-part "r"))
     (define sig-r-data (gcry_sexp_nth_data sig-r-part 1))
     (define sig-s-part (gcry_sexp_find_token sig-part "s"))
     (define sig-s-data (gcry_sexp_nth_data sig-s-part 1))
     (gcry_sexp_release sig-r-part)
     (gcry_sexp_release sig-s-part)
     (gcry_sexp_release sig-part)
     (unless (and (= PARTLEN (bytes-length sig-r-data))
                  (= PARTLEN (bytes-length sig-s-data)))
       (crypto-error "failed; implementation returned ill-formed result"))
     (bytes-append sig-r-data sig-s-data))

   (define (verify-make-sig-sexp sig-bytes curve)
     (define PARTLEN (case curve [(ed25519) 32] [(ed448) 57]))
     (define SIGLEN (* 2 PARTLEN))
     (and (= (bytes-length sig-bytes) SIGLEN)
          (make-sexp `(sig-val (eddsa (r ,(subbytes sig-bytes 0 PARTLEN))
                                      (s ,(subbytes sig-bytes PARTLEN SIGLEN)))))))
   ))

;; ============================================================

(struct gcrypt-ecx-impl gcrypt-pk-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %]
             [pk*$ #:prefix %])

   (define (%pk-generate-params self config)
     (check-config config config:ecx-keygen #:in self)
     (define curve (config-ref config 'curve))
     (curve->params self curve))

   (define (curve->params self curve)
     (unless (curve-ok? curve) (err/no-curve curve self))
     (pk-parameters self curve))

   (define (curve-ok? curve)
     (case curve [(x25519) x25519-ok?] [(x448) x448-ok?] [else #f]))

   (define (get-keylen curve)
     (case curve [(x25519) 32] [(x448) 56]))

   ;; ----

   (define (%pkp-generate-key self pkp)
     (define curve ($pkp-param-values self pkp))
     (define priv (crypto-random-bytes (get-keylen curve)))
     (ecx-clamp-secret! curve priv)
     (define pub (compute-pub curve priv))
     (pk-key self (keypair curve pub priv) #t))

   (define (%pkp-param-values self pkp)
     (define curve-name (ctx-inner pkp))
     curve-name)

   (define (compute-pub curve priv)
     (define pub (make-bytes (get-keylen curve)))
     (case curve
       [(x25519) (gcry_ecc_mul_point GCRY_ECC_CURVE25519 pub priv #f)]
       [(x448) (gcry_ecc_mul_point GCRY_ECC_CURVE448 pub priv #f)])
     pub)

   ;; ----

   (define (%pkk-write-key self pkk fmt)
     (match-define (keypair curve pub priv) (ctx-inner pkk))
     (cond [priv (encode-priv-ecx fmt curve pub priv)]
           [else (encode-pub-ecx fmt curve pub)]))

   ;; ---- pk*

   (define (%pk*-make-params self curve)
     (and (curve-ok? curve) (curve->params curve)))

   (define (%pk*-make-public-key self curve qB)
     (cond [(curve-ok? curve)
            (unless (= (bytes-length qB) (get-keylen curve))
              (crypto-error "invalid public key (wrong length)" #:in self))
            (pk-key self (keypair curve qB #f) #f)]
           [else #f]))

   (define (%pk*-make-private-key self curve qB dB)
     (cond [(curve-ok? curve)
            (define len (get-keylen curve))
            (unless (= (bytes-length dB) len)
              (crypto-error "invalid private key (wrong length)" #:in self))
            (when (and qB (not (= (bytes-length dB) len)))
              (crypto-error "invalid public key (wrong length)" #:in self))
            (define priv (bytes-copy dB))
            (ecx-clamp-secret! curve priv)
            (define pub (compute-pub curve priv))
            (when qB (check-recomputed-qB pub qB))
            (pk-key self (keypair curve pub priv) #t)]
           [else #f]))

   (define (make-ec-public-key curve qB)
     (make-sexp `(public-key (ecc (curve ,curve) (q ,qB)))))

   (define (make-ec-private-key curve qB d)
     (define priv
       (make-sexp `(private-key (ecc (curve ,curve)
                                     (q ,qB)
                                     (d ,(unsigned->base256 d))))))
     (gcry_pk_testkey priv)
     priv)

   ;; ----

   (define (%pkk*-compute-secret self pkk peer-pubkey)
     (match-define (keypair curve pub priv) (ctx-inner pkk))
     (define peer (keypair-pub (ctx-inner peer-pubkey)))
     (case curve
       [(x25519)
        (define result (make-bytes 32))
        (gcry_ecc_mul_point GCRY_ECC_CURVE25519 result priv peer)
        result]
       [(x448)
        (define result (make-bytes 56))
        (gcry_ecc_mul_point GCRY_ECC_CURVE448 result priv peer)
        result]))

   (define (%pkk*-import-for-key-agree self pkk bs)
     (define curve (keypair-param (ctx-inner pkk)))
     ($pk*-make-public-key self curve bs))
   ))
