;; Copyright 2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         racket/string
         ffi/unsafe
         asn1
         brandx
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/pk-common.rkt"
         "../common/error.rkt"
         "../common/base256.rkt"
         "ffi.rkt")
(provide libcrypto3-fetch-pk)

(define (libcrypto3-fetch-pk factory info)
  (define spec ($get-spec info))
  (case spec
    [(rsa) (libcrypto3-rsa-impl info factory)]
    [(dsa) (libcrypto3-dsa-impl info factory)]
    [(dh)  (libcrypto3-dh-impl info factory)]
    [(ec)  (libcrypto3-ec-impl info factory)]
    [(eddsa) (libcrypto3-eddsa-impl info factory)]
    [(ecx) (libcrypto3-ecx-impl info factory)]
    [else #f]))

;; ============================================================

;; libcrypto3-write-key : PKKey Symbol -> Bytes/#f
;; Not used by pk-key->datum, but retained for debugging/testing.
(define (libcrypto3-write-key pkk fmt)
  (match-define (pk-key impl evp private?) pkk)
  (case fmt
    [(SubjectPublicKeyInfo)
     (HANDLEp (i2d_PUBKEY evp))]
    [(PrivateKeyInfo)
     (and private?
          (HANDLEp (i2d_PKCS8_PRIV_KEY_INFO (HANDLEp (EVP_PKEY2PKCS8 evp)))))]
    [else #f]))

;; libcrypto3-read-key : Bytes Symbol -> pkey/#f
;; Not used by datum->pk-key, but retained for debugging/testing.
(define (libcrypto3-read-key factory sk fmt)
  (define libctx ($factory-inner-ctx factory))
  (unless (bytes? sk)
    (raise-argument-error 'libcrypto3-read-key "bytes?" sk))
  (define (make-key evp private?)
    (define impl (and evp (evp->impl factory evp)))
    (and impl (if private? (evp->private-key impl evp) (evp->public-key impl evp))))
  (case fmt
    [(SubjectPublicKeyInfo)
     (make-key (HANDLEp (d2i_PUBKEY_ex sk (bytes-length sk) libctx #f)))]
    [(PrivateKeyInfo)
     (define p (HANDLEp (d2i_PKCS8_PRIV_KEY_INFO sk (bytes-length sk))))
     (make-key (HANDLEp (EVP_PKCS82PKEY_ex p libctx #f)) #t)]
    [else #f]))

(define (evp->impl factory evp)
  (define spec
    (cond [(EVP_PKEY_is_a evp "RSA") 'rsa]
          [(EVP_PKEY_is_a evp "DSA") 'dsa]
          [(EVP_PKEY_is_a evp "DH") 'dh] ;; or DHX?
          [(EVP_PKEY_is_a evp "EC") 'ec]
          [(or (EVP_PKEY_is_a evp "ED25519")
               (EVP_PKEY_is_a evp "ED448"))
           'eddsa]
          [(or (EVP_PKEY_is_a evp "X25519")
               (EVP_PKEY_is_a evp "X448"))
           'ecx]
          [else #f]))
  (and spec ($fetch-pk factory spec)))

(define (pk-libctx impl)
  ($factory-inner-ctx ($get-factory impl)))

(define (evp-ok? impl evp mode)
  (and evp
       (let ([ctx (EVP_PKEY_CTX_new_from_pkey (pk-libctx impl) evp #f)])
         (HANDLEp (EVP_PKEY_param_check ctx)
                  #:or-fail-with "key parameters validation failed")
         (case mode
           [(public) (HANDLEp (EVP_PKEY_public_check ctx)
                              #:or-fail-with "public key validation failed")]
           [(private) (HANDLEp (EVP_PKEY_check ctx)
                               #:or-fail-with "private key validation failed")]))))

(define (evp->params impl evp)
  (and (evp-ok? impl evp 'params)
       (pk-parameters impl evp)))

(define (evp->public-key impl evp)
  (and (evp-ok? impl evp 'public)
       (pk-key impl evp #f)))

(define (evp->private-key impl evp)
  (and (evp-ok? impl evp 'private)
       (pk-key impl evp #t)))

(define (evp-copy impl evp selection)
  (define data (EVP_PKEY_todata evp selection))
  (define keytype (EVP_PKEY_get0_type_name evp))
  (begin0 (fromdata* impl keytype selection data)
    (OSSL_PARAM_free data)
    (void/reference-sink keytype)))

;; fromdata : PKImpl Bytes Symbol ParamList/#f -> EVP_PKEY
(define (fromdata impl keytype mode params)
  (define selection
    (case mode
      [(params)  EVP_PKEY_KEY_PARAMETERS]
      [(public)  EVP_PKEY_PUBLIC_KEY]
      [(private) EVP_PKEY_KEYPAIR]))
  (define paramsarray (make-param-array params))
  (fromdata* impl keytype selection paramsarray))

;; fromdata* : PKImpl Bytes Int OSSL_PARAM-array -> EVP_PKEY
(define (fromdata* impl keytype selection paramsarray)
  (define keytype-ptr (nonmoving keytype))
  (define ctx (HANDLEp (EVP_PKEY_CTX_new_from_name (pk-libctx impl) keytype-ptr #f)))
  (HANDLEp (EVP_PKEY_fromdata_init ctx))
  (begin0 (HANDLEp (EVP_PKEY_fromdata ctx selection paramsarray))
    (void/reference-sink keytype-ptr)))

;; generate-key-from-pevp : PKImpl EVP_PKEY -> PK-Key
(define (generate-key-from-pevp impl pevp)
  (define ctx (HANDLEp (EVP_PKEY_CTX_new_from_pkey (pk-libctx impl) pevp #f)))
  (HANDLEp (EVP_PKEY_keygen_init ctx))
  (define kevp (HANDLEp (EVP_PKEY_generate ctx)))
  (evp->private-key impl kevp))

;; generate-params : PKImpl Bytes Params -> PKParameters
(define (generate-params impl keytype params)
  (define libctx (pk-libctx impl))
  (define keytype-ptr (nonmoving keytype))
  (define ctx (HANDLEp (EVP_PKEY_CTX_new_from_name libctx keytype-ptr #f)))
  (HANDLEp (EVP_PKEY_paramgen_init ctx))
  (HANDLEp (EVP_PKEY_CTX_set_params ctx (make-param-array params)))
  (define pevp (HANDLEp (EVP_PKEY_generate ctx)
                        #:or-fail-with "parameter generation failed"))
  (void/reference-sink keytype-ptr)
  (evp->params impl pevp))

;; ----------------------------------------

(define (pkk-sign pkk msg params)
  (define evp (ctx-inner pkk))
  (define libctx (pk-libctx (ctx-impl pkk)))
  (evp-sign evp libctx msg params))

(define (pkk-verify pkk msg params sig)
  (define evp (ctx-inner pkk))
  (define libctx (pk-libctx (ctx-impl pkk)))
  (evp-verify evp libctx msg params sig))

(define (evp-sign evp libctx msg params)
  (define msglen (bytes-length msg))
  (define ctx (HANDLEp (EVP_PKEY_CTX_new_from_pkey libctx evp #f)))
  (HANDLEp (EVP_PKEY_sign_init_ex ctx (make-param-array params)))
  (define siglen (HANDLEp (EVP_PKEY_sign ctx #f 0 msg msglen)))
  (define sigbuf (make-bytes siglen))
  (define siglen2 (HANDLEp (EVP_PKEY_sign ctx sigbuf siglen msg msglen)))
  (subbytes sigbuf 0 siglen2))

(define (evp-verify evp libctx msg params sig)
  (define ctx (HANDLEp (EVP_PKEY_CTX_new_from_pkey libctx evp #f)))
  (HANDLEp (EVP_PKEY_verify_init_ex ctx (make-param-array params)))
  (NOERR (EVP_PKEY_verify ctx sig (bytes-length sig) msg (bytes-length msg))))

;; ----------------------------------------

(define (pkk-encrypt pkk msg params)
  (define evp (ctx-inner pkk))
  (define libctx (pk-libctx (ctx-impl pkk)))
  (evp-encrypt evp libctx msg params))

(define (pkk-decrypt pkk msg params)
  (define evp (ctx-inner pkk))
  (define libctx (pk-libctx (ctx-impl pkk)))
  (evp-decrypt evp libctx msg params))

(define (evp-encrypt evp libctx msg params)
  (define msglen (bytes-length msg))
  (define ctx (HANDLEp (EVP_PKEY_CTX_new_from_pkey libctx evp #f)))
  (HANDLEp (EVP_PKEY_encrypt_init_ex ctx (make-param-array params)))
  (define outlen (HANDLEp (EVP_PKEY_encrypt ctx #f 0 msg msglen)))
  (define outbuf (make-bytes outlen))
  (define outlen2 (HANDLEp (EVP_PKEY_encrypt ctx outbuf outlen msg msglen)))
  (subbytes outbuf 0 outlen2))

(define (evp-decrypt evp libctx msg params)
  (define msglen (bytes-length msg))
  (define ctx (HANDLEp (EVP_PKEY_CTX_new_from_pkey libctx evp #f)))
  (HANDLEp (EVP_PKEY_decrypt_init_ex ctx (make-param-array params)))
  (define outlen (HANDLEp (EVP_PKEY_decrypt ctx #f 0 msg msglen)))
  (define outbuf (make-bytes outlen))
  (define outlen2 (HANDLEp (EVP_PKEY_decrypt ctx outbuf outlen msg msglen)))
  (subbytes outbuf 0 outlen2))

;; ----------------------------------------

(define (pkk-compute-secret pkk peer-pkk params)
  (define evp (ctx-inner pkk))
  (define libctx (pk-libctx (ctx-impl pkk)))
  (define peer-evp (ctx-inner peer-pkk))
  (evp-compute-secret evp libctx peer-evp params))

(define (evp-compute-secret evp libctx peer-evp params)
  (define ctx (HANDLEp (EVP_PKEY_CTX_new_from_pkey libctx evp #f)))
  (HANDLEp (EVP_PKEY_derive_init_ex ctx (make-param-array params)))
  (HANDLEp (EVP_PKEY_derive_set_peer_ex ctx peer-evp #t))
  (define outlen (HANDLEp (EVP_PKEY_derive ctx #f 0)))
  (define buf (make-bytes outlen))
  (define outlen2 (HANDLEp (EVP_PKEY_derive ctx buf (bytes-length buf))))
  (subbytes buf 0 outlen2))

(define signing-digests
  ;; https://docs.openssl.org/master/man3/EVP_DigestSignInit/
  ;; but the following seem to be accepted in practice
  '(sha1
    sha224 sha256 sha384 sha512 sha512/224 sha512/256
    sha3-224 sha3-256 sha3-384 sha3-512))

;; ============================================================
;; Base

(struct libcrypto3-pk-impl-base pk-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %])

   ;; ---- pkp

   (define (%pkp-generate-key self pkp)
     (generate-key-from-pevp self (ctx-inner pkp)))

   (define (%pkp-security-bits self pkp)
     (EVP_PKEY_get_security_bits (ctx-inner pkp)))

   (define (%pkp-equal? self pkp1 pkp2)
     (define evp1 (ctx-inner pkp1))
     (define evp2 (ctx-inner pkp2))
     (NOERR (EVP_PKEY_parameters_eq evp1 evp2)))

   ;; ---- pkk

   (define (%pkk-public-key self pkk)
     (match-define (pk-key _ evp private?) pkk)
     (if private? (evp->public-key self (evp-copy self evp EVP_PKEY_PUBLIC_KEY)) pkk))

   ;; XXXX!!!! not if param is curve name
   (define (%pkk-params self pkk)
     (evp->params self (evp-copy self (ctx-inner pkk) EVP_PKEY_KEY_PARAMETERS)))

   (define (%pkk-security-bits self pkk)
     (EVP_PKEY_get_security_bits (ctx-inner pkk)))

   (define (%pkk-equal-public? self pkk1 pkk2)
     (define evp1 (ctx-inner ($pkk-public-key self pkk1)))
     (define evp2 (ctx-inner ($pkk-public-key self pkk2)))
     (NOERR (EVP_PKEY_eq evp1 evp2)))

   (define (%pkk-equal-params? self pkk1 pkk2)
     (define evp1 (ctx-inner pkk1))
     (define evp2 (ctx-inner pkk2))
     (NOERR (EVP_PKEY_parameters_eq evp1 evp2)))
   ))

;; ============================================================
;; RSA

(struct libcrypto3-rsa-impl libcrypto3-pk-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %]
             [pk*$ #:prefix %])

   ;; ---- pk-info

   (define (%pk-can-sign? self pad dspec)
     (and (memq pad '(#f pkcs1-v1.5 pss pss*))
          (or (memq dspec signing-digests)
              (memq dspec '(md5 md4 md2)))
          (and (send factory get-digest dspec) #t)))

   (define (%pk-can-encrypt? self pad)
     (and (memq pad '(#f pkcs1-v1.5 oaep)) #t))

   ;; ---- pk-impl

   (define (%pk-generate-key self config)
     (define-values (nbits e)
       (check/ref-config '(nbits e) config config:rsa-keygen #:in self))
     (cond [e
            (define params (make-param-array
                            `((#"bits" uint ,nbits)
                              (#"e" uint ,e #:?))))
            (define keytype (nonmoving #"rsa"))
            (define ctx (HANDLEp (EVP_PKEY_CTX_new_from_name (pk-libctx self) keytype #f)))
            (HANDLEp (EVP_PKEY_keygen_init ctx))
            (HANDLEp (EVP_PKEY_CTX_set_params ctx params))
            (define evp (HANDLEp (EVP_PKEY_generate ctx)))
            (void/reference-sink keytype)
            (evp->private-key self evp)]
           [else
            (define evp (HANDLEp (EVP_PKEY_Q_keygen/RSA (get-libctx) #f nbits)))
            (evp->private-key self evp)]))

   (define (%pkk-write-key self pkk fmt)
     (match-define (pk-key _ evp private?) pkk)
     (define n (HANDLEp (EVP_PKEY_get_bn_param/value evp #"n")))
     (define e (HANDLEp (EVP_PKEY_get_bn_param/value evp #"e")))
     (cond [private?
            (define d (HANDLEp (EVP_PKEY_get_bn_param/value evp #"d")))
            (define p (HANDLEp (EVP_PKEY_get_bn_param/value evp #"rsa-factor1")))
            (define q (HANDLEp (EVP_PKEY_get_bn_param/value evp #"rsa-factor2")))
            (define dp (HANDLEp (EVP_PKEY_get_bn_param/value evp #"rsa-exponent1")))
            (define dq (HANDLEp (EVP_PKEY_get_bn_param/value evp #"rsa-exponent2")))
            (define qInv (HANDLEp (EVP_PKEY_get_bn_param/value evp #"rsa-coefficient1")))
            ;; Writing keys with >2 prime factors is not supported.
            (cond [(NOERR (EVP_PKEY_get_bn_param/value evp #"rsa-factor3")) #f]
                  [else (encode-priv-rsa fmt n e d p q dp dq qInv)])]
           [else
            (encode-pub-rsa fmt n e)]))

   ;; ---- pkk*

   (define (%pk*-make-public-key self n e)
     (define evp (fromdata self #"RSA" 'public (make-fromdata-params n e #f #f #f #f #f #f)))
     (evp->public-key self evp))
   (define (%pk*-make-private-key self n e d p q dp dq qInv)
     (define evp (fromdata self #"RSA" 'private (make-fromdata-params n e d p q dp dq qInv)))
     (evp->private-key self evp))

   (define (make-fromdata-params self n e d p q dp dq qInv)
     (define derive? (and n e d p q (not (and dp dq qInv))))
     `((#"n" ubignum ,n)
       (#"e" ubignum ,e)
       (#"d" ubignum ,d #:?)
       (#"rsa-factor1" ubignum ,p #:?)
       (#"rsa-factor2" ubignum ,q #:?)
       (#"rsa-exponent1" ubignum ,dp #:?)
       (#"rsa-exponent2" ubignum ,dq #:?)
       (#"rsa-coefficient1" ubignum ,qInv #:?)
       (#"rsa-derive-from-pq" uint ,(and derive? 1) #:?)))

   (define (%pkk*-sign self pkk msg dspec pad)
     (pkk-sign pkk msg (get-sign/verify-params self #t dspec pad)))

   (define (%pkk*-verify self pkk msg dspec pad sig)
     (pkk-sign pkk msg (get-sign/verify-params self #f dspec pad) sig))

   (define (get-sign/verify-params self sign? dspec pad)
     (define dname (get-digest-lcname dspec))
     (case pad
       [(pkcs1-v1.5 #f)
        `((#"digest" utf8-string ,dname)
          (#"pad-mode" utf8-string "pkcs1"))]
       [(pss)
        `((#"digest" utf8-string ,dname)
          (#"pad-mode" utf8-string "pss")
          (#"saltlen" utf8-string "digest"))]
       [(pss*)
        `((#"digest" utf8-string ,dname)
          (#"pad-mode" utf8-string "pss")
          (#"saltlen" utf8-string ,(if sign? "digest" "auto")))]
       [else (err/bad-signature-pad self pad)]))

   (define (%pkk*-encrypt self pkk msg pad)
     (pkk-encrypt pkk msg (get-encrypt/decrypt-params self #t pad)))

   (define (%pkk*-decrypt self pkk msg pad)
     (pkk-decrypt pkk msg (get-encrypt/decrypt-params self #f pad)))

   (define (get-encrypt/decrypt-params self enc? pad)
     (case pad
       [(oaep #f) `((#"pad-mode" utf8-string "oaep"))]
       [(pkcs1-v1.5) `((#"pad-mode" utf8-string "pkcs1"))]
       [else (err/bad-encrypt-pad self pad)]))
   ))

;; ============================================================
;; DSA

(struct libcrypto3-dsa-impl libcrypto3-pk-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %]
             [pk*$ #:prefix %])

   ;; ---- pk-impl

   (define (%pk-generate-params self config)
     (define-values (nbits qbits)
       (check/ref-config '(nbits qbits) config config:dsa-paramgen #:in self))
     (define params
       `((#"pbits" uint ,nbits #:?)
         (#"qbits" uint ,qbits #:?)))
     (generate-params self #"DSA" params))

   (define (%pkp-write-params self pkp fmt)
     (define-values (p q g) (dsa-evp-get-params (ctx-inner pkp)))
     (encode-params-dsa fmt p q g))

   (define (%pkp-param-values self pkp)
     (dsa-evp-get-params (ctx-inner pkp)))

   (define (%pkk-write-key self pkk fmt)
     (match-define (pk-key _ evp private?) pkk)
     (define-values (p q g) (dsa-evp-get-params evp))
     (define pub (HANDLEp (EVP_PKEY_get_bn_param/value evp #"pub")))
     (cond [private?
            (define priv (HANDLEp (EVP_PKEY_get_bn_param/value evp #"priv")))
            (encode-priv-dsa fmt p q g pub priv)]
           [else (encode-pub-dsa fmt p q g pub)]))

   (define (dsa-evp-get-params pevp)
     (define p (HANDLEp (EVP_PKEY_get_bn_param/value pevp #"p")))
     (define q (HANDLEp (EVP_PKEY_get_bn_param/value pevp #"q")))
     (define g (HANDLEp (EVP_PKEY_get_bn_param/value pevp #"g")))
     (values p q g))

   ;; ---- pkk*

   (define (%pk*-make-params self p q g)
     (define evp (fromdata self #"DSA" 'params (make-fromdata-params p q g #f #f)))
     (evp->params self evp))
   (define (%pk*-make-public-key self p q g y)
     (define evp (fromdata self #"DSA" 'public (make-fromdata-params p q g y #f)))
     (evp->public-key self evp))
   (define (%pk*-make-private-key self p q g y x)
     (define evp (fromdata self #"DSA" 'private (make-fromdata-params p q g y x)))
     (evp->private-key self evp))

   (define (make-fromdata-params p q g y x)
     `((#"p" ubignum ,p)
       (#"q" ubignum ,q)
       (#"g" ubignum ,g)
       (#"pub" ubignum ,y #:?)
       (#"priv" ubignum ,x #:?)))

   (define (%pkk*-sign self pkk msg dspec pad)
     (pkk-sign pkk msg (get-sign/verify-params self #t dspec pad)))

   (define (%pkk*-verify self pkk msg dspec pad sig)
     (pkk-sign pkk msg (get-sign/verify-params self #f dspec pad) sig))

   (define (get-sign/verify-params self sign? dspec pad)
     (unless (eq? pad #f) (err/bad-signature-pad self pad))
     ;; DSA does not include the digest identity in the signature
     ;; calculation; this should only cause a length check.
     (cond [(memq dspec signing-digests)
            (define dname (get-digest-lcname dspec))
            `((#"digest" utf8-string ,dname))]
           [else '()]))
   ))

;; ============================================================
;; DH

(struct libcrypto3-dh-impl libcrypto3-pk-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %]
             [pk*$ #:prefix %])

   ;; ---- pk-impl

   (define (%pk-generate-params self config)
     (define-values (nbits generator)
       (check/ref-config '(nbits generator) config config:dh-paramgen "DH paramgen"))
     (define params `((#"pbits" uint ,nbits #:?)
                      #;(#"qbits" uint ,qbits #:?)
                      (#"g" uint ,generator #:?)))
     (generate-params self #"DH" params))

   (define (%pkp-write-params self pkp fmt)
     (define-values (p g q j seed pgen) (dh-evp-get-params (ctx-inner pkp)))
     (encode-params-dh fmt p g q j seed pgen))

   (define (%pkp-param-values self pkp)
     (dh-evp-get-params (ctx-inner pevp)))

   (define (%pkk-write-key self pkk fmt)
     (match-define (pk-key _ evp private?) pkk)
     (define-values (p g q j seed pgen) (dh-evp-get-params evp))
     (define pub (HANDLEp (EVP_PKEY_get_bn_param/value evp #"pub")))
     (cond [private?
            (define priv (HANDLEp (EVP_PKEY_get_bn_param/value evp #"priv")))
            (encode-priv-dh fmt p g q j seed pgen pub priv)]
           [else (encode-pub-dh fmt p g q j seed pgen pub)]))

   (define (dh-evp-get-params pevp)
     (define p (HANDLEp (EVP_PKEY_get_bn_param/value pevp #"p")))
     (define g (HANDLEp (EVP_PKEY_get_bn_param/value pevp #"g")))
     (define q (NOERR (EVP_PKEY_get_bn_param/value pevp #"q")))
     (define j (NOERR (EVP_PKEY_get_bn_param/value pevp #"j")))
     (define seed (NOERR (EVP_PKEY_get_bn_param/value pevp #"seed")))
     (define pgen (NOERR (EVP_PKEY_get_bn_param/value pevp #"pcounter")))
     (values p g q j seed pgen))

   ;; ---- pkk*

   (define (%pk*-make-params self p g q j seed pgen)
     (define evp (fromdata self #"DH" 'params (make-fromdata-params p g q j seed pgen #f #f)))
     (evp->params self evp))
   (define (%pk*-make-public-key self p g q j seed pgen y)
     (define evp (fromdata self #"DH" 'public (make-fromdata-params p g q j seed pgen y #f)))
     (evp->public-key self evp))
   (define (%pk*-make-private-key self p g q j seed pgen y x)
     (define evp (fromdata self #"DH" 'private (make-fromdata-params p g q j seed pgen y x)))
     (evp->private-key self evp))

   (define (make-fromdata-params p g q j seed pgen y x)
     `((#"p" ubignum ,p)
       (#"g" ubignum ,g)
       (#"q" ubignum ,q #:?)
       (#"j" ubignum ,j #:?)
       (#"seed" octet-string ,(and seed pgen seed) #:?)
       (#"pcounter" uint ,(and seed pgen pgen) #:?)
       (#"pub" ubignum ,y #:?)
       (#"priv" ubignum ,x #:?)))

   (define (%pkk*-compute-secret self pkk peer-pkk)
     (define params `((#"pad" uint 1)))
     (pkk-compute-secret pkk peer-pkk params))
   ))

#;
(define (libcrypto3-named-params group)
  ;; Group is one of:
  ;; - 'ffdhe2048 'ffdhe3072 'ffdhe4096 'ffdhe6144 'ffdhe8192
  ;; - 'modp_2048 'modp_3072 'modp_4096 'modp_6144 'modp_8192
  ;; - 'modp_1536 'dh_1024_160 'dh_2048_224 'dh_2048_256
  (evp->params (fromdata #"DHX" 'params `((#"group" utf8-string ,(symbol->string group))))))

;; ============================================================
;; EC

(struct libcrypto3-ec-impl libcrypto3-pk-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %]
             [pk*$ #:prefix %])

   ;; ---- pk-impl

   (define (%pk-generate-key self config)
     (define curve (check/ref-config '(curve) config config:ec-paramgen #:in self))
     (define curve-lcname (curve-alias->lcname curve))
     (and curve-lcname
          (let ([evp (HANDLEp (EVP_PKEY_Q_keygen/EC (get-libctx) #f curve-lcname)
                              #:or-fail-with "key generation failed")])
            (evp->private-key self evp))))

   (define (%pk-generate-params self config)
     (define curve (check/ref-config '(curve) config config:ec-paramgen #:in self))
     (define curve-lcname (curve-alias->lcname curve))
     (and curve-lcname
          (let ([params `((#"group" utf8-string ,curve-lcname))])
            (evp->params self (fromdata self #"EC" 'params params)))))

   (define (%pkp-write-params self pkp fmt)
     (define curve-oid (%pkp-param-values self pkp))
     (encode-params-ec fmt curve-oid))

   (define (%pkp-param-values self pkp)
     (define pevp (ctx-inner pkp))
     (define curve-lcname (HANDLEp (EVP_PKEY_get_utf8_string_param/value evp #"group")))
     (and curve-lcname (curve-lcname->oid curve-lcname)))

   (define (%pkk-write-key self pkk fmt)
     (match-define (pk-key _ evp private?) pkk)
     (define curve-lcname (HANDLEp (EVP_PKEY_get_utf8_string_param/value evp #"group")))
     (define curve-oid (and curve-lcname (curve-lcname->oid curve-lcname)))
     (define pub (HANDLEp (EVP_PKEY_get_octet_string_param/value evp #"encoded-pub-key")))
     (cond [private?
            (define priv (HANDLEp (EVP_PKEY_get_bn_param/value evp #"priv")))
            (and curve-oid pub priv (encode-priv-ec fmt curve-oid pub priv))]
           [else (and curve-oid pub (encode-pub-ec fmt curve-oid pub))]))

   #;
   (define (get-curve self pkp)
     (define curve-lcname
       (NOERR (EVP_PKEY_get_utf8_string_param/value pevp #"group")))
     (cond [curve-lcname (curve-lcname->name curve-lcname)]
           [else (internal-error "unable to fetch curve name")]))

   ;; ---- pkk*

   (define (%pk*-make-params self curve-oid)
     (define curve-lcname (curve-oid->lcname curve-oid))
     (and curve-lcname
          (let ([params (make-fromdata-params curve-lcname #f #f)])
            (evp->params self (fromdata self #"EC" 'params params)))))
   (define (%pk*-make-public-key self curve-oid qB)
     (define curve-lcname (curve-oid->lcname curve-oid))
     (and curve-lcname
          (let ([params (make-fromdata-params curve-lcname qB #f)])
            (evp->public-key self (fromdata self #"EC" 'public params)))))
   (define (%pk*-make-private-key self curve-oid qB x)
     (define curve-lcname (curve-oid->lcname curve-oid))
     (and curve-lcname
          (let ([params (make-fromdata-params curve-lcname qB x)])
            (evp->private-key self (fromdata self #"EC" 'private params)))))

   (define (make-fromdata-params curve-oid qB x)
     `((#"group" utf8-string ,curve-lcname)
       (#"pub" octet-string ,qB #:?)
       (#"priv" ubignum ,x #:?)))

   (define (%pkk*-sign self pkk msg dspec pad)
     (pkk-sign pkk msg (get-sign/verify-params self #t dspec pad)))

   (define (%pkk*-verify self pkk msg dspec pad sig)
     (pkk-sign pkk msg (get-sign/verify-params self #f dspec pad) sig))

   (define (get-sign/verify-params self sign? dspec pad)
     (unless (eq? pad #f) (err/bad-signature-pad this pad))
     ;; ECDSA does not include the digest identity in the signature
     ;; calculation; this should only cause a length check.
     (cond [(memq dspec signing-digests)
            (define dname (get-digest-lcname dspec))
            `((#"digest" utf8-string ,dname))]
           [else '()]))

   (define (%pkk*-compute-secret self pkk peer-pkk)
     (pkk-compute-secret pkk peer-pkk '()))
   ))

;; ============================================================
;; EdDSA

(struct libcrypto3-eddsa-impl libcrypto3-pk-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %]
             [pk*$ #:prefix %])

   ;; ---- pk-impl

   (define (%pk-generate-key self config)
     (define libctx (pk-libctx self))
     (define curve (check/ref-config '(curve) config config:eddsa-keygen #:in self))
     (match curve
       ['ed25519
        (define evp (HANDLEp (EVP_PKEY_Q_keygen/none libctx #f "ED25519")))
        (evp->private-key self evp)]
       ['ed448
        (define evp (HANDLEp (EVP_PKEY_Q_keygen/none libctx #f "ED448")))
        (evp->private-key self evp)]))

   (define (%pk-generate-params self config)
     (define curve (check/ref-config '(curve) config config:eddsa-keygen #:in self))
     (pk-parameters self curve))

   (define (%pkp-write-params self pkp fmt)
     (define curve (%pkp-param-values self pkp))
     (encode-params-eddsa fmt curve))

   (define (%pkp-param-values self pkp)
     (evp->curve (ctx-inner pkp)))

   (define (%pkk-write-key self pkk fmt)
     (match-define (pk-key _ evp private?) pkk)
     (define curve (evp->curve evp))
     (define pub (HANDLEp (EVP_PKEY_get_octet_string_param/value evp #"pub")))
     (cond [private?
            (define priv (HANDLEp (EVP_PKEY_get_octet_string_param/value evp #"priv")))
            (and pub priv (encode-priv-eddsa fmt curve pub priv))]
           [else (and pub (encode-pub-eddsa fmt curve pub))]))

   (define (evp->curve evp)
     (cond [(EVP_PKEY_is_a evp "ED25519") 'ed25519]
           [(EVP_PKEY_is_a evp "ED448") 'ed448]
           [else (internal-error "unknown EdDSA curve")]))

   ;; ---- pkk*

   (define (%pk*-make-params self curve)
     (pk-parameters self curve))
   (define (%pk*-make-public-key self curve qB)
     (define evp (fromdata self (curve->keytype curve) 'public (make-fromdata-params qB #f)))
     (evp->public-key self evp))
   (define (%pk*-make-private-key self curve qB dB)
     (define evp (fromdata self (curve->keytype curve) 'private (make-fromdata-params qB dB)))
     (evp->private-key self evp))

   (define (make-fromdata-params qB dB)
     `((#"pub" octet-string ,qB #:?)
       (#"priv" octet-string ,dB #:?)))

   (define (curve->keytype curve)
     (match curve
       ['ed25519 #"ED25519"]
       ['ed448 #"ED448"]))

   (define (%pkk*-sign self pkk msg _dspec _pad)
     (define libctx (pk-libctx self))
     (define evp (ctx-inner pkk))
     (define mdctx (HANDLEp (EVP_MD_CTX_new)))
     (define params (make-param-array '()))
     (HANDLEp (EVP_DigestSignInit_ex mdctx #f (get-libctx) #f evp params))
     (define msglen (bytes-length msg))
     (define siglen (HANDLEp (EVP_DigestSign mdctx #f 0 msg msglen)))
     (define sigbuf (make-bytes siglen))
     (define siglen2 (HANDLEp (EVP_DigestSign mdctx sigbuf siglen msg msglen)))
     (subbytes sigbuf 0 siglen2))

   (define (%pkk*-verify self pkk msg _dspec _pad sig)
     (define libctx (pk-libctx self))
     (define evp (ctx-inner pkk))
     (define mdctx (HANDLEp (EVP_MD_CTX_new)))
     (define params (make-param-array '()))
     (HANDLEp (EVP_DigestVerifyInit_ex mdctx #f (get-libctx) #f evp params))
     (NOERR (EVP_DigestVerify mdctx sig (bytes-length sig) msg (bytes-length msg))))
   ))

;; ============================================================
;; ECX

(struct libcrypto3-ecx-impl libcrypto3-pk-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %]
             [pk*$ #:prefix %])

   ;; ---- pk-impl

   (define (%pk-generate-key self config)
     (define curve (check/ref-config '(curve) config config:ecx-keygen #:in self))
     (define keytype
       (match curve
         ['x25519 "X25519"]
         ['x448 "X448"]))
     (define libctx (pk-libctx self))
     (define evp (HANDLEp (EVP_PKEY_Q_keygen/none libctx #f keytype)))
     (evp->private-key self evp))

   (define (%pk-generate-params self config)
     (define curve (check/ref-config '(curve) config config:ecx-keygen #:in self))
     (pk-parameters self curve))

   (define (%pkp-write-params self pkp fmt)
     (encode-params-ecx fmt (evp->curve (ctx-inner pkp))))

   (define (%pkp-param-values self pkp)
     (evp->curve (ctx-inner pkp)))

   (define (%pkk-write-key self pkk fmt)
     (match-define (pk-key _ evp private?) pkk)
     (define curve (evp->curve evp))
     (define pub (HANDLEp (EVP_PKEY_get_octet_string_param/value evp #"pub")))
     (cond [private?
            (define priv (HANDLEp (EVP_PKEY_get_octet_string_param/value evp #"priv")))
            (and pub priv (encode-priv-ecx fmt curve pub priv))]
           [else (and pub (encode-pub-ecx fmt curve pub))]))

   (define (evp->curve evp)
     (cond [(EVP_PKEY_is_a evp "X25519") 'x25519]
           [(EVP_PKEY_is_a evp "X448") 'x448]
           [else (internal-error "unknown ECX curve")]))

   ;; ---- pkk*

   (define (%pk*-make-params self curve)
     (pk-parameters self curve))
   (define (%pk*-make-public-key self curve qB)
     (define evp (fromdata self (curve->keytype curve) 'public (make-fromdata-params qB #f)))
     (evp->public-key self evp))
   (define (%pk*-make-private-key self curve qB dB)
     (define evp (fromdata self (curve->keytype curve) 'private (make-fromdata-params qB dB)))
     (evp->private-key self evp))

   (define (make-fromdata-params qB dB)
     `((#"pub" octet-string ,qB #:?)
       (#"priv" octet-string ,dB #:?)))

   (define (curve->keytype curve)
     (match curve
       ['x25519 #"X25519"]
       ['x448 #"X448"]))

   (define (%pkk*-compute-secret self pkk peer-pkk)
     (pkk-compute-secret pkk peer-pkk null))

   (define (%pkk*-import-for-key-agree self pkk peer-pubkey)
     (define curve (evp->curve (ctx-inner pkk)))
     ($pk*-make-public-key self curve peer-pubkey))
   ))

;; ============================================================

;; CurveInfo = (curveinfo Symbol Nat OID String)
(struct curveinfo (name nid oid lcname) #:prefab)

;; get-all-curve-names : -> (Listof Symbol)
(define (get-all-curve-names)
  (map curveinfo-name all-curveinfos))

;; curve-oid->lcname : OID -> String/#f
;; Returns #f if curve not available.
(define (curve-oid->lcname oid)
  (define ci (hash-ref oid=>curveinfo oid #f))
  (and ci (curveinfo-lcname ci)))

;; curve-alias->lcname : Symbol -> String/#f
;; Returns #f if curve not available.
(define (curve-alias->lcname alias)
  (define ci (hash-ref name=>curveinfo (alias->curve-name alias) #f))
  (and ci (curveinfo-lcname ci)))

;; curve-lcname->name : String -> Symbol
(define (curve-lcname->name lcname)
  (define ci (hash-ref lcname=>curveinfo lcname #f))
  (and ci (curveinfo-name ci)))

;; curve-lcname->oid : String -> OID
(define (curve-lcname->oid lcname)
  (define ci (hash-ref lcname=>curveinfo lcname #f))
  (and ci (curveinfo-oid ci)))

;; all-curveinfos : (Listof CurveInfo)
(define all-curveinfos
  (let ([bad-curves '(SM2)])
    ;; Add builtin curves
    (define curve-count (EC_get_builtin_curves #f 0))
    (define ci-base (malloc curve-count _EC_builtin_curve 'atomic))
    (cpointer-push-tag! ci-base EC_builtin_curve-tag)
    (EC_get_builtin_curves ci-base curve-count)
    (for/fold ([all-cis null]) ([i (in-range curve-count)])
      (define ci (ptr-add ci-base i _EC_builtin_curve))
      (define nid (EC_builtin_curve-nid ci))
      (define lcname (string->immutable-string (OBJ_nid2sn nid)))
      (define oid-str (and nid (OBJ_obj2txt (OBJ_nid2obj nid))))
      (define oid (and oid-str (map string->number (string-split oid-str "."))))
      (define name (alias->curve-name lcname))
      (cond [(memq name bad-curves) all-cis]
            [else (cons (curveinfo name nid oid lcname) all-cis)]))))

(define oid=>curveinfo
  (for/hash ([ci (in-list all-curveinfos)]) (values (curveinfo-oid ci) ci)))
(define name=>curveinfo
  (for/hasheq ([ci (in-list all-curveinfos)]) (values (curveinfo-name ci) ci)))
(define lcname=>curveinfo
  (for/hash ([ci (in-list all-curveinfos)]) (values (curveinfo-lcname ci) ci)))
