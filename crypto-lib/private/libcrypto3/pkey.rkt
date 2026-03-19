;; Copyright 2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

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

(define libcrypto3-read-key%
  (class pk-read-key-base%
    (inherit-field factory)
    (super-new (spec 'libcrypto3-read-key))

    (define/private (get-libctx) (send factory get-libctx))

    ;; libcrypto-read-key : Bytes Symbol -> pkey/#f
    ;; Not used by datum->pk-key, but retained for debugging/testing.
    (define/public (libcrypto-read-key sk fmt)
      (unless (bytes? sk)
        (raise-argument-error 'libcrypto-read-key "bytes?" sk))
      (define (make-key evp private?)
        (define impl (and evp (evp->impl evp)))
        (cond [private? (and impl (send impl evp->private-key evp))]
              [else (and impl (send impl evp->public-key evp))]))
      (define (evp->impl evp)
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
        (and spec (send factory get-pk spec)))
      (case fmt
        [(SubjectPublicKeyInfo)
         (make-key (HANDLEp (d2i_PUBKEY_ex sk (bytes-length sk) (get-libctx) #f)))]
        [(PrivateKeyInfo)
         (define p (HANDLEp (d2i_PKCS8_PRIV_KEY_INFO sk (bytes-length sk))))
         (make-key (HANDLEp (EVP_PKCS82PKEY_ex p (get-libctx) #f)) #t)]
        [else #f]))
    ))

;; ============================================================
;; Base

(define libcrypto3-pk-impl%
  (class pk-impl-base%
    (inherit-field factory)
    (super-new)

    (define/public (get-libctx) (send factory get-libctx))

    (define/public (evp->params evp)
      (and evp (new (get-params-class) (impl this) (pevp evp))))
    (define/public (evp->public-key evp)
      (and evp (new (get-key-class) (impl this) (evp evp) (private? #f))))
    (define/public (evp->private-key evp)
      (and evp (new (get-key-class) (impl this) (evp evp) (private? #t))))

    (define/public (get-params-class) (err/no-impl this))
    (define/public (get-key-class) (err/no-impl this))

    ;; fromdata : String Int ParamList/#f -> EVP_PKEY/#f
    (define/public (fromdata keytype mode params)
      (define selection
        (case mode
          [(params)  EVP_PKEY_KEY_PARAMETERS]
          [(public)  EVP_PKEY_PUBLIC_KEY]
          [(private) EVP_PKEY_KEYPAIR]))
      (define keytype-ptr (nonmoving keytype))
      (define ctx (HANDLEp (EVP_PKEY_CTX_new_from_name (get-libctx) keytype-ptr #f)))
      (HANDLEp (EVP_PKEY_fromdata_init ctx))
      (define paramsarray (make-param-array params))
      (define evp (HANDLEp (EVP_PKEY_fromdata ctx selection paramsarray)))
      (void/reference-sink keytype-ptr)
      ;; FIXME: EVP_PKEY_check, etc
      evp)

    ;; generate-key-from-pevp : EVP_PKEY -> PK-Key
    (define/public (generate-key-from-pevp pevp)
      (define ctx (HANDLEp (EVP_PKEY_CTX_new_from_pkey (get-libctx) pevp #f)))
      (HANDLEp (EVP_PKEY_keygen_init ctx))
      (define kevp (HANDLEp (EVP_PKEY_generate ctx)))
      (evp->private-key kevp))

    ;; generate-key-from-params : PK-Params -> PK-Key
    (define/public (generate-key-from-params pkp)
      (generate-key-from-pevp (get-field pevp pkp)))
    ))

(define (libcrypto3-pk-params-mixin base%)
  (class base%
    (init-field pevp)
    (super-new)

    (define/override (get-security-bits)
      (EVP_PKEY_get_security_bits pevp))
    ))

;; ----------------------------------------

(define libcrypto3-pk-key%
  (class pk-key-base%
    (init-field evp private?)
    (inherit-field impl)
    (super-new)

    (define/public (get-libctx) (send impl get-libctx))

    (define/override (get-security-bits)
      (EVP_PKEY_get_security_bits evp))

    (define/override (is-private?) private?)

    (define/override (get-public-key)
      ;; FIXME: check this doesn't lose information (eg, DHX vs DH)
      (define pub (HANDLEp (i2d_PUBKEY evp)))
      (define pub-evp (HANDLEp (d2i_PUBKEY_ex pub (bytes-length pub) (get-libctx) #f)))
      (send impl evp->public-key pub-evp))

    (define/override (get-params)
      (cond [private? (send (get-public-key) get-params)]
            [else (send impl evp->params evp)]))

    ;; libcrypto-write-key : Symbol -> Bytes/#f
    ;; Not used by pk-key->datum, but retained for debugging/testing.
    (define/public (libcrypto-write-key fmt)
      (case fmt
        [(SubjectPublicKeyInfo)
         (HANDLEp (i2d_PUBKEY evp))]
        [(PrivateKeyInfo)
         (and private?
              (HANDLEp (i2d_PKCS8_PRIV_KEY_INFO (HANDLEp (EVP_PKEY2PKCS8 evp)))))]
        [else #f]))

    (define/override (equal-to-key? other)
      (and (is-a? other libcrypto3-pk-key%)
           (NOERR (EVP_PKEY_eq evp (get-field evp other)))))

    ;; ----------------------------------------
    ;; Encrypt

    (define/override (-encrypt msg pad)
      (define msglen (bytes-length msg))
      (define ctx (HANDLEp (EVP_PKEY_CTX_new_from_pkey (get-libctx) evp #f)))
      (define params (make-param-array (-get-encrypt/decrypt-params #t pad)))
      (HANDLEp (EVP_PKEY_encrypt_init_ex ctx params))
      (define outlen (HANDLEp (EVP_PKEY_encrypt ctx #f 0 msg msglen)))
      (define outbuf (make-bytes outlen))
      (define outlen2 (HANDLEp (EVP_PKEY_encrypt ctx outbuf outlen msg msglen)))
      (subbytes outbuf 0 outlen2))

    (define/override (-decrypt msg pad)
      (define msglen (bytes-length msg))
      (define ctx (HANDLEp (EVP_PKEY_CTX_new_from_pkey (get-libctx) evp #f)))
      (define params (make-param-array (-get-encrypt/decrypt-params #f pad)))
      (HANDLEp (EVP_PKEY_decrypt_init_ex ctx params))
      (define outlen (HANDLEp (EVP_PKEY_decrypt ctx #f 0 msg msglen)))
      (define outbuf (make-bytes outlen))
      (define outlen2 (HANDLEp (EVP_PKEY_decrypt ctx outbuf outlen msg msglen)))
      (subbytes outbuf 0 outlen2))

    (define/public (-get-encrypt/decrypt-params enc? pad) '())

    ;; ----------------------------------------
    ;; Sign and Verify

    (define/override (-sign digest dspec pad)
      (define digestlen (bytes-length digest))
      (define ctx (HANDLEp (EVP_PKEY_CTX_new_from_pkey (get-libctx) evp #f)))
      (define params (make-param-array (-get-sign/verify-params #t pad dspec)))
      (HANDLEp (EVP_PKEY_sign_init_ex ctx params))
      (define siglen (HANDLEp (EVP_PKEY_sign ctx #f 0 digest digestlen)))
      (define sigbuf (make-bytes siglen))
      (define siglen2 (HANDLEp (EVP_PKEY_sign ctx sigbuf siglen digest digestlen)))
      (subbytes sigbuf 0 siglen2))

    (define/override (-verify digest dspec pad sig)
      (define ctx (HANDLEp (EVP_PKEY_CTX_new_from_pkey (get-libctx) evp #f)))
      (define params (make-param-array (-get-sign/verify-params #f pad dspec)))
      (HANDLEp (EVP_PKEY_verify_init_ex ctx params))
      (NOERR (EVP_PKEY_verify ctx sig (bytes-length sig) digest (bytes-length digest))))

    (define/public (-get-sign/verify-params sign? pad dspec)
      ;; Default: require pad=#f, ignore digest
      (unless (eq? pad #f) (err/bad-signature-pad this pad))
      '())

    ;; ----------------------------------------
    ;; Key exchange

    (define/override (-compute-secret peer-pubkey)
      ;; PRE: peer-pubkey is libcrypto-pk-key% with same impl
      (define peer-evp (get-field evp peer-pubkey))
      (define ctx (HANDLEp (EVP_PKEY_CTX_new_from_pkey (get-libctx) evp #f)))
      (define params (make-param-array (-get-keyexch-params)))
      (HANDLEp (EVP_PKEY_derive_init_ex ctx params))
      (HANDLEp (EVP_PKEY_derive_set_peer_ex ctx peer-evp #t))
      (define outlen (HANDLEp (EVP_PKEY_derive ctx #f 0)))
      (define buf (make-bytes outlen))
      (define outlen2 (HANDLEp (EVP_PKEY_derive ctx buf (bytes-length buf))))
      (subbytes buf 0 outlen2))

    (define/public (-get-keyexch-params) '())

    (define/override (-compatible-for-key-agree? peer-pubkey)
      ;; PRE: peer-pubkey is libcrypto-pk-key% with same impl
      (NOERR (EVP_PKEY_parameters_eq evp (get-field evp peer-pubkey))))
    ))

(define signing-digests
  ;; https://docs.openssl.org/master/man3/EVP_DigestSignInit/
  ;; but the following seem to be accepted in practice
  '(sha1
    sha224 sha256 sha384 sha512 sha512/224 sha512/256
    sha3-224 sha3-256 sha3-384 sha3-512))

;; ============================================================
;; RSA

(define libcrypto3-rsa-impl%
  (class libcrypto3-pk-impl%
    (inherit-field factory)
    (inherit get-libctx evp->public-key evp->private-key fromdata)
    (super-new (spec 'rsa))

    (define/override (get-key-class) libcrypto3-rsa-key%)

    (define/override (can-encrypt? pad)
      (and (memq pad '(#f pkcs1-v1.5 oaep)) #t))
    (define/override (can-sign pad) 'depends)
    (define/override (can-sign2? pad dspec)
      (and (memq pad '(#f pkcs1-v1.5 pss pss*))
           (or (memq dspec signing-digests)
               (memq dspec '(md5 md4 md2)))
           (and (send factory get-digest dspec) #t)))

    (define/override (make-public-key n e)
      (evp->public-key (fromdata #"RSA" 'public
                                 (make-fromdata-params n e #f #f #f #f #f #f))))
    (define/override (make-private-key n e d p q dp dq qInv)
      (evp->private-key (fromdata #"RSA" 'private
                                  (make-fromdata-params n e d p q dp dq qInv))))

    (define/private (make-fromdata-params n e d p q dp dq qInv)
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

    (define/override (generate-key config)
      (define-values (nbits e)
        (check/ref-config '(nbits e) config config:rsa-keygen "RSA keygen"))
      (cond [e
             (define params (make-param-array
                             `((#"bits" uint ,nbits)
                               (#"e" uint ,e #:?))))
             (define keytype (nonmoving #"rsa"))
             (define ctx (HANDLEp (EVP_PKEY_CTX_new_from_name (get-libctx) keytype #f)))
             (HANDLEp (EVP_PKEY_keygen_init ctx))
             (HANDLEp (EVP_PKEY_CTX_set_params ctx params))
             (define evp (HANDLEp (EVP_PKEY_generate ctx)))
             (void/reference-sink keytype)
             (evp->private-key evp)]
            [else
             (define evp (HANDLEp (EVP_PKEY_Q_keygen/RSA (get-libctx) #f nbits)))
             (evp->private-key evp)]))
    ))

;; ----------------------------------------

(define libcrypto3-rsa-key%
  (class libcrypto3-pk-key%
    (inherit-field impl evp private?)
    (super-new)

    (define/override (-write-key fmt)
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

    (define/override (-get-encrypt/decrypt-params enc? pad)
      (case pad
        [(oaep #f) `((#"pad-mode" utf8-string "oaep"))]
        [(pkcs1-v1.5) `((#"pad-mode" utf8-string "pkcs1"))]
        [else (err/bad-encrypt-pad this pad)]))

    (define/override (-get-sign/verify-params sign? pad dspec)
      (define factory (send impl get-factory))
      (define dname (send factory get-digest-lcname dspec))
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
        [else (err/bad-signature-pad this pad)]))
    ))

;; ============================================================
;; DSA

(define libcrypto3-dsa-impl%
  (class libcrypto3-pk-impl%
    (inherit-field factory)
    (inherit evp->params evp->public-key evp->private-key fromdata get-libctx)
    (super-new (spec 'dsa))

    (define/override (can-sign pad) (and (memq pad '(#f)) 'ignoredg))
    (define/override (has-params?) #t)

    (define/override (get-params-class) libcrypto3-dsa-params%)
    (define/override (get-key-class) libcrypto3-dsa-key%)

    (define/override (make-params p q g)
      (evp->params (fromdata #"DSA" 'params
                             (make-fromdata-params p q g #f #f))))
    (define/override (make-public-key p q g y)
      (evp->public-key (fromdata #"DSA" 'public
                                 (make-fromdata-params p q g y #f))))
    (define/override (make-private-key p q g y x)
      (evp->private-key (fromdata #"DSA" 'private
                                  (make-fromdata-params p q g y x))))

    (define/private (make-fromdata-params p q g y x)
      `((#"p" ubignum ,p)
        (#"q" ubignum ,q)
        (#"g" ubignum ,g)
        (#"pub" ubignum ,y #:?)
        (#"priv" ubignum ,x #:?)))

    (define/override (generate-params config)
      (define-values (nbits qbits)
        (check/ref-config '(nbits qbits) config config:dsa-paramgen "DSA paramgen"))
      (define dsa-ptr (nonmoving #"DSA"))
      (define ctx (HANDLEp (EVP_PKEY_CTX_new_from_name (get-libctx) dsa-ptr #f)))
      (HANDLEp (EVP_PKEY_paramgen_init ctx))
      (define params (make-param-array
                      `((#"pbits" uint ,nbits #:?)
                        (#"qbits" uint ,qbits #:?))))
      (HANDLEp (EVP_PKEY_CTX_set_params ctx params))
      (define pevp (HANDLEp (EVP_PKEY_generate ctx)
                            #:or-fail-with "parameter generation failed"))
      (void/reference-sink dsa-ptr)
      (evp->params pevp))
    ))

(define libcrypto3-dsa-params%
  (class (libcrypto3-pk-params-mixin pk-dsa-params%)
    (inherit-field impl pevp)
    (super-new)

    (define/override (-write-params fmt)
      (define-values (p q g) (dsa-evp-get-params pevp))
      (encode-params-dsa fmt p q g))

    (define/override (get-param-values)
      (dsa-evp-get-params pevp))
    ))

(define (dsa-evp-get-params pevp)
  (define p (HANDLEp (EVP_PKEY_get_bn_param/value pevp #"p")))
  (define q (HANDLEp (EVP_PKEY_get_bn_param/value pevp #"q")))
  (define g (HANDLEp (EVP_PKEY_get_bn_param/value pevp #"g")))
  (values p q g))

;; ----------------------------------------

(define libcrypto3-dsa-key%
  (class libcrypto3-pk-key%
    (inherit get-params)
    (inherit-field impl evp private?)
    (super-new)

    (define/override (-write-key fmt)
      (define-values (p q g) (dsa-evp-get-params evp))
      (define pub (HANDLEp (EVP_PKEY_get_bn_param/value evp #"pub")))
      (cond [private?
             (define priv (HANDLEp (EVP_PKEY_get_bn_param/value evp #"priv")))
             (encode-priv-dsa fmt p q g pub priv)]
            [else (encode-pub-dsa fmt p q g pub)]))

    (define/override (-get-sign/verify-params sign? pad dspec)
      (unless (eq? pad #f) (err/bad-signature-pad this pad))
      ;; DSA does not include the digest identity in the signature
      ;; calculation; this should only cause a length check.
      (cond [(memq dspec signing-digests)
             (define factory (send impl get-factory))
             (define dname (send factory get-digest-lcname dspec))
             `((#"digest" utf8-string ,dname))]
            [else '()]))
    ))

;; ============================================================
;; DH

(define libcrypto3-dh-impl%
  (class libcrypto3-pk-impl%
    (inherit evp->params evp->public-key evp->private-key fromdata get-libctx)
    (super-new (spec 'dh))

    (define/override (can-key-agree?) #t)
    (define/override (has-params?) #t)

    (define/override (get-params-class) libcrypto3-dh-params%)
    (define/override (get-key-class) libcrypto3-dh-key%)

    (define/override (make-params p g q j seed pgen)
      (evp->params (fromdata #"DH" 'params
                             (make-fromdata-params p g q j seed pgen #f #f))))
    (define/override (make-public-key p g q j seed pgen y)
      (evp->public-key (fromdata #"DH" 'public
                                 (make-fromdata-params p g q j seed pgen y #f))))
    (define/override (make-private-key p g q j seed pgen y x)
      (evp->private-key (fromdata #"DH" 'private
                                  (make-fromdata-params p g q j seed pgen y x))))

    (define/private (make-fromdata-params p g q j seed pgen y x)
      `((#"p" ubignum ,p)
        (#"g" ubignum ,g)
        (#"q" ubignum ,q #:?)
        (#"j" ubignum ,j #:?)
        (#"seed" octet-string ,(and seed pgen seed) #:?)
        (#"pcounter" uint ,(and seed pgen pgen) #:?)
        (#"pub" ubignum ,y #:?)
        (#"priv" ubignum ,x #:?)))

    (define/override (generate-params config)
      (define-values (nbits generator)
        (check/ref-config '(nbits generator) config config:dh-paramgen "DH paramgen"))
      (define dh-ptr (nonmoving #"DH"))
      (define ctx (HANDLEp (EVP_PKEY_CTX_new_from_name (get-libctx) dh-ptr #f)))
      (HANDLEp (EVP_PKEY_paramgen_init ctx))
      (define params (make-param-array
                      `((#"pbits" uint ,nbits #:?)
                        #;(#"qbits" uint ,qbits #:?)
                        (#"g" uint ,generator #:?))))
      (HANDLEp (EVP_PKEY_CTX_set_params ctx params))
      (define pevp (HANDLEp (EVP_PKEY_generate ctx)
                            #:or-fail-with "parameter generation failed"))
      (void/reference-sink dh-ptr)
      (evp->params pevp))

    (define/public (libcrypto-named-params group)
      ;; Group is one of:
      ;; - 'ffdhe2048 'ffdhe3072 'ffdhe4096 'ffdhe6144 'ffdhe8192
      ;; - 'modp_2048 'modp_3072 'modp_4096 'modp_6144 'modp_8192
      ;; - 'modp_1536 'dh_1024_160 'dh_2048_224 'dh_2048_256
      (evp->params (fromdata #"DHX" 'params
                             `((#"group" utf8-string ,(symbol->string group))))))
    ))

(define libcrypto3-dh-params%
  (class (libcrypto3-pk-params-mixin pk-dh-params%)
    (inherit-field impl pevp)
    (super-new)

    (define/override (-write-params fmt)
      (define-values (p g q j seed pgen) (dh-evp-get-params pevp))
      (encode-params-dh fmt p g q j seed pgen))

    (define/override (get-param-values)
      (dh-evp-get-params pevp))
    ))

(define (dh-evp-get-params pevp)
  (define p (HANDLEp (EVP_PKEY_get_bn_param/value pevp #"p")))
  (define g (HANDLEp (EVP_PKEY_get_bn_param/value pevp #"g")))
  (define q (NOERR (EVP_PKEY_get_bn_param/value pevp #"q")))
  (define j (NOERR (EVP_PKEY_get_bn_param/value pevp #"j")))
  (define seed (NOERR (EVP_PKEY_get_bn_param/value pevp #"seed")))
  (define pgen (NOERR (EVP_PKEY_get_bn_param/value pevp #"pcounter")))
  (values p g q j seed pgen))

;; ----------------------------------------

(define libcrypto3-dh-key%
  (class libcrypto3-pk-key%
    (inherit get-params)
    (inherit-field impl evp private?)
    (super-new)

    (define/override (-write-key fmt)
      (define-values (p g q j seed pgen) (dh-evp-get-params evp))
      (define pub (HANDLEp (EVP_PKEY_get_bn_param/value evp #"pub")))
      (cond [private?
             (define priv (HANDLEp (EVP_PKEY_get_bn_param/value evp #"priv")))
             (encode-priv-dh fmt p g q j seed pgen pub priv)]
            [else (encode-pub-dh fmt p g q j seed pgen pub)]))

    (define/override (-get-keyexch-params)
      `((#"pad" uint 1)))
    ))

;; ============================================================
;; EC

(define libcrypto3-ec-impl%
  (class libcrypto3-pk-impl%
    (inherit-field factory)
    (inherit evp->params evp->public-key evp->private-key fromdata get-libctx)
    (super-new (spec 'ec))

    (define/override (can-sign pad) (and (memq pad '(#f)) 'ignoredg))
    (define/override (can-key-agree?) #t)
    (define/override (has-params?) #t)

    (define/override (get-params-class) libcrypto3-ec-params%)
    (define/override (get-key-class) libcrypto3-ec-key%)

    (define/override (make-params curve-oid)
      (define curve-name (curve-oid->lcname curve-oid))
      (and curve-name
           (let ([params (make-fromdata-params curve-name #f #f)])
             (evp->params (fromdata #"EC" 'params params)))))
    (define/override (make-public-key curve-oid qB)
      (define curve-name (curve-oid->lcname curve-oid))
      (and curve-name
           (let ([params (make-fromdata-params curve-name qB #f)])
             (evp->public-key (fromdata #"EC" 'public params)))))
    (define/override (make-private-key curve-oid qB x)
      (define curve-name (curve-oid->lcname curve-oid))
      (and curve-name
           (let ([params (make-fromdata-params curve-name qB x)])
             (evp->private-key (fromdata #"EC" 'private params)))))

    (define/private (make-fromdata-params curve-name qB x)
      `((#"group" utf8-string ,curve-name)
        (#"pub" octet-string ,qB #:?)
        (#"priv" ubignum ,x #:?)))

    (define/override (generate-params config)
      (define curve (check/ref-config '(curve) config config:ec-paramgen "EC paramgen"))
      (define curve-name (curve-alias->lcname curve))
      (and curve-name
           (let ([params `((#"group" utf8-string ,curve-name))])
             (evp->params (fromdata #"EC" 'params params)))))

    (define/override (generate-key config)
      (define curve (check/ref-config '(curve) config config:ec-paramgen "EC keygen"))
      (define curve-name (curve-name->lcname curve))
      (and curve-name
           (evp->private-key (HANDLEp (EVP_PKEY_Q_keygen/EC (get-libctx) #f curve-name)
                                      #:or-fail-with "key generation failed"))))
    ))

(define libcrypto3-ec-params%
  (class (libcrypto3-pk-params-mixin pk-ec-params%)
    (inherit-field impl pevp)
    (super-new)

    (define/override (get-curve)
      (define curve-lcname
        (NOERR (EVP_PKEY_get_utf8_string_param/value pevp #"group")))
      (cond [curve-lcname (curve-lcname->name curve-lcname)]
            [else (internal-error "unable to fetch curve name")]))
    ))

;; ----------------------------------------

(define libcrypto3-ec-key%
  (class libcrypto3-pk-key%
    (inherit-field impl evp private?)
    (super-new)

    (define/override (-write-key fmt)
      (define curve-lcname (HANDLEp (EVP_PKEY_get_utf8_string_param/value evp #"group")))
      (define curve-oid (and curve-lcname (curve-lcname->oid curve-lcname)))
      (define pub (HANDLEp (EVP_PKEY_get_octet_string_param/value evp #"encoded-pub-key")))
      (cond [private?
             (define priv (HANDLEp (EVP_PKEY_get_bn_param/value evp #"priv")))
             (and curve-oid pub priv (encode-priv-ec fmt curve-oid pub priv))]
            [else (and curve-oid pub (encode-pub-ec fmt curve-oid pub))]))

    (define/override (-get-sign/verify-params sign? pad dspec)
      (unless (eq? pad #f) (err/bad-signature-pad this pad))
      ;; ECDSA does not include the digest identity in the signature
      ;; calculation; this should only cause a length check.
      (cond [(memq dspec signing-digests)
             (define factory (send impl get-factory))
             (define dname (send factory get-digest-lcname dspec))
             `((#"digest" utf8-string ,dname))]
            [else '()]))
    ))

;; ============================================================
;; EdDSA

(define libcrypto3-eddsa-impl%
  (class libcrypto3-pk-impl%
    (inherit evp->public-key evp->private-key fromdata get-libctx)
    (super-new (spec 'eddsa))

    (define/override (can-sign pad) (and (memq pad '(#f)) 'nodigest))
    (define/override (has-params?) #t)

    (define/override (get-key-class) libcrypto3-eddsa-key%)

    (define/override (make-params curve)
      (new pk-eddsa-params% (impl this) (curve curve)))
    (define/override (make-public-key curve qB)
      (evp->public-key (fromdata (curve->keytype curve) 'public
                                 (make-fromdata-params qB #f))))
    (define/override (make-private-key curve qB dB)
      (evp->private-key (fromdata (curve->keytype curve) 'private
                                  (make-fromdata-params qB dB))))

    (define/private (make-fromdata-params qB dB)
      `((#"pub" octet-string ,qB #:?)
        (#"priv" octet-string ,dB #:?)))

    (define/private (curve->keytype curve)
      (case curve [(ed25519) #"ED25519"] [(ed448) #"ED448"] [else #f]))

    (define/override (generate-params config)
      (define curve
        (check/ref-config '(curve) config config:eddsa-keygen "EDDSA paramgen"))
      ;; FIXME: check that curve is available?
      (make-params curve))

    (define/override (generate-key config)
      (define curve
        (check/ref-config '(curve) config config:eddsa-keygen "EDDSA keygen"))
      (generate-key-from-curve curve))

    (define/public (generate-key-from-curve curve)
      (case curve
        [(ed25519)
         (define evp (HANDLEp (EVP_PKEY_Q_keygen/none (get-libctx) #f "ED25519")))
         (evp->private-key evp)]
        [(ed448)
         (define evp (HANDLEp (EVP_PKEY_Q_keygen/none (get-libctx) #f "ED448")))
         (evp->private-key evp)]
        [else #f]))
    ))

;; ----------------------------------------

(define libcrypto3-eddsa-key%
  (class libcrypto3-pk-key%
    (inherit get-libctx)
    (inherit-field impl evp private?)
    (super-new)

    (define/override (get-params)
      (send impl make-params (get-curve)))

    (define/public (get-curve)
      (cond [(EVP_PKEY_is_a evp "ED25519") 'ed25519]
            [(EVP_PKEY_is_a evp "ED448") 'ed448]
            [else (internal-error "unknown EdDSA curve")]))

    (define/override (-write-key fmt)
      (define curve (get-curve))
      (define pub (HANDLEp (EVP_PKEY_get_octet_string_param/value evp #"pub")))
      (cond [private?
             (define priv (HANDLEp (EVP_PKEY_get_octet_string_param/value evp #"priv")))
             (and pub priv (encode-priv-eddsa fmt curve pub priv))]
            [else (and pub (encode-pub-eddsa fmt curve pub))]))

    (define/override (-sign msg _dspec _pad)
      (define mdctx (HANDLEp (EVP_MD_CTX_new)))
      (define params (make-param-array '()))
      (HANDLEp (EVP_DigestSignInit_ex mdctx #f (get-libctx) #f evp params))
      (define msglen (bytes-length msg))
      (define siglen (HANDLEp (EVP_DigestSign mdctx #f 0 msg msglen)))
      (define sigbuf (make-bytes siglen))
      (define siglen2 (HANDLEp (EVP_DigestSign mdctx sigbuf siglen msg msglen)))
      (subbytes sigbuf 0 siglen2))

    (define/override (-verify msg _dspec _pad sig)
      (define mdctx (HANDLEp (EVP_MD_CTX_new)))
      (define params (make-param-array '()))
      (HANDLEp (EVP_DigestVerifyInit_ex mdctx #f (get-libctx) #f evp params))
      (NOERR (EVP_DigestVerify mdctx sig (bytes-length sig) msg (bytes-length msg))))
    ))

;; ============================================================
;; ECX

(define libcrypto3-ecx-impl%
  (class libcrypto3-pk-impl%
    (inherit evp->public-key evp->private-key fromdata get-libctx)
    (super-new (spec 'ecx))

    (define/override (can-key-agree?) #t)
    (define/override (has-params?) #t)

    (define/override (get-key-class) libcrypto3-ecx-key%)

    (define/override (make-params curve)
      (new pk-ecx-params% (impl this) (curve curve)))
    (define/override (make-public-key curve qB)
      (evp->public-key (fromdata (curve->keytype curve) 'public
                                 (make-fromdata-params qB #f))))
    (define/override (make-private-key curve qB dB)
      (evp->private-key (fromdata (curve->keytype curve) 'private
                                  (make-fromdata-params qB dB))))

    (define/private (make-fromdata-params qB dB)
      `((#"pub" octet-string ,qB #:?)
        (#"priv" octet-string ,dB #:?)))

    (define/private (curve->keytype curve)
      (case curve [(x25519) #"X25519"] [(x448) #"X448"] [else #f]))

    (define/override (generate-params config)
      (define curve
        (check/ref-config '(curve) config config:ecx-keygen "ECX paramgen"))
      ;; FIXME: check that curve is available
      (make-params curve))

    (define/override (generate-key config)
      (define curve
        (check/ref-config '(curve) config config:ecx-keygen "ECX keygen"))
      (generate-key-from-curve curve))

    (define/public (generate-key-from-curve curve)
      (case curve
        [(x25519)
         (define evp (HANDLEp (EVP_PKEY_Q_keygen/none (get-libctx) #f "X25519")))
         (evp->private-key evp)]
        [(x448)
         (define evp (HANDLEp (EVP_PKEY_Q_keygen/none (get-libctx) #f "X448")))
         (evp->private-key evp)]
        [else #f]))
    ))

;; ----------------------------------------

(define libcrypto3-ecx-key%
  (class libcrypto3-pk-key%
    (inherit-field impl evp private?)
    (super-new)

    (define/override (get-params)
      (send impl make-params (get-curve)))

    (define/public (get-curve)
      (cond [(EVP_PKEY_is_a evp "X25519") 'x25519]
            [(EVP_PKEY_is_a evp "X448") 'x448]
            [else (internal-error "unknown ECX curve")]))

    (define/override (-write-key fmt)
      (define curve (get-curve))
      (define pub (HANDLEp (EVP_PKEY_get_octet_string_param/value evp #"pub")))
      (cond [private?
             (define priv (HANDLEp (EVP_PKEY_get_octet_string_param/value evp #"priv")))
             (and pub priv (encode-priv-ecx fmt curve pub priv))]
            [else (and pub (encode-pub-ecx fmt curve pub))]))

    (define/override (-convert-for-key-agree bs)
      (send impl make-public-key (get-curve) bs))
    ))

;; ============================================================

;; curve-oid->lcname : OID -> String/#f
;; Returns #f if curve not available.
(define (curve-oid->lcname curve-oid)
  (curve-name->lcname (curve-oid->name curve-oid)))

;; curve-name->lcname : Symbol -> String/#f
;; Returns #f if curve not available.
(define (curve-name->lcname name)
  (hash-ref curve-name=>lcname name #f))

;; curve-alias->lcname : Symbol -> String/#f
;; Returns #f if curve not available.
(define (curve-alias->lcname alias)
  (curve-name->lcname (alias->curve-name alias)))

;; curve-lcname->name : String -> Symbol
(define (curve-lcname->name lcname)
  (hash-ref curve-lcname=>name lcname))

;; curve-lcname->oid : String -> OID
(define (curve-lcname->oid lcname)
  (curve-name->oid (curve-lcname->name lcname)))

;; curve-name=>lcname : Hash[Symbol => String]
;; curve-lcname=>name : Hash[Symbol => String]
;; Maps between catalog name and libcrypto name.
(define-values (curve-name=>lcname curve-lcname=>name)
  (let ([bad-curves '(SM2)])
    ;; Add builtin curves
    (define curve-count (EC_get_builtin_curves #f 0))
    (define ci-base (malloc curve-count _EC_builtin_curve 'atomic))
    (cpointer-push-tag! ci-base EC_builtin_curve-tag)
    (EC_get_builtin_curves ci-base curve-count)
    (for/fold ([n=>lc (hasheq)] [lc=>n (hash)])
              ([i (in-range curve-count)])
      (define ci (ptr-add ci-base i _EC_builtin_curve))
      (define nid (EC_builtin_curve-nid ci))
      (define libcrypto-name (string->immutable-string (OBJ_nid2sn nid)))
      (define name (alias->curve-name libcrypto-name))
      (cond [(memq name bad-curves) (values n=>lc lc=>n)]
            [else (values (hash-set n=>lc name libcrypto-name)
                          (hash-set lc=>n libcrypto-name name))]))))
