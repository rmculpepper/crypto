;; Copyright 2012 Ryan Culpepper
;; Copyright 2007-2009 Dimitris Vyzovitis <vyzo at media.mit.edu>
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
         racket/class
         racket/match
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/error.rkt"
         "ffi.rkt"
         "digest.rkt")
(provide (all-defined-out))

#|
Key formats
 - PKCS1 (RSA only)
 - SubjectPublicKeyInfo ({i2d,d2i}_PUBKEY) (public key only)
 - PKCS8 DER/PEM (private key only, optional encryption/password)
   - for DSA, format actually specified by PKCS11 v2.01 section 11.9
 - {i2d,d2i}_{Private,Public}Key uses *some* format, possibly ad hoc
   d2i needs to be told what kind of key expected
 - {d2i,i2d}_{PublicKey,PrivateKey} doesn't seem to work on EC keys
 - {d2i,i2d}_PUBKEY encodes key as SubjectPublicKeyInfo (ie, includes type of key)
 - PKCS#8 might handle all kinds of private keys
   - {d2i,i2d}_PKCS8_PRIV_KEY_INFO(...);
   - EVP_PKEY *EVP_PKCS82PKEY(PKCS8_PRIV_KEY_INFO *p8);
   - PKCS8_PRIV_KEY_INFO *EVP_PKEY2PKCS8(EVP_PKEY *pkey);
 - Nope, both PUBKEY and PKCS8_PRIV_KEY_INFO functions also crash on EC keys.
 - ECPKParameters vs ECParameters
   - according to http://www.faqs.org/rfcs/rfc3279.html:
     ECPKParameters = CHOICE { ECParameters | ...}

References:
 - https://groups.google.com/forum/#!topic/mailing.openssl.users/HsiN-8Lt0H8
 - http://openssl.6102.n7.nabble.com/difference-between-i2d-PUBKEY-and-i2d-PublicKey-td43869.html
 - http://www.openssl.org/docs/crypto/pem.html

 - http://www.ietf.org/rfc/rfc2459.txt
   encodings including SubjectPublicKeyInfo
 - http://tools.ietf.org/html/rfc5480
   Elliptic Curve Cryptography Subject Public Key Information


Generating keys & params for testing:

  openssl genrsa -out rsa-512.key 512
  openssl rsa -inform pem -outform der -in rsa-512.key -out rsa-512.der
  (bytes->private-key rsai (file->bytes "rsa-512.der"))

  openssl dsaparam -outform pem -out dsa-512.params 512
  openssl gendsa -out dsa-512.key dsa-512.params
  openssl dsa -inform pem -outform der -in dsa-512.key -out dsa-512.der
  (bytes->private-key dsai (file->bytes "dsa-512.der"))

Key Agreement
 - generate shared params => params%
 - generate private key-part => key%
 - compute shared secret from private key-part and public key-part (?) => bytes
   - Note: result is biased, not uniform, so unsuitable as key!
 - compute key from shared secret
   - eg, use digest (see RFC 2631)

TODO: check params (eg safe primes) on generate-params OR read-params

TODO: support predefined DH params
 - http://tools.ietf.org/html/rfc3526
 - http://tools.ietf.org/html/rfc5114

|#

#|
Key Format

The 'libcrypto key format:

 - (list 'libcrypto (U 'rsa 'dsa 'ec) 'private key-bytes)
   for 'rsa: key-bytes is PKCS#1 RSAPrivateKey
   for 'dsa: key-bytes is ???
   for 'ec:  key-bytes is SEC1 ECPrivateKey
 - (list 'libcrypto (U 'rsa 'dsa 'ec) 'public key-bytes)
   for 'rsa and 'dsa: key-bytes is SubjectPublicKeyInfo (citation???)
   for 'ec: key-bytes is an octet string representation of an EC_POINT (citation???)

 - (list 'libcrypto 'dh 'private param-bytes pubkey-bytes privkey-bytes)
 - (list 'libcrypto 'dh 'public  param-bytes pubkey-bytes)
   param-bytes is PKCS#3 DHParameter
   pubkey-bytes is unsigned binary rep of public key bignum
   privkey-bytes is unsigned binary rep of private key bignum

The 'libcrypto params format:

 - (list 'libcrypto (U 'dsa 'dh 'ec) params-bytes)
   for 'dsa: key-bytes is ???
   for 'dh:  params-bytes is PKCS#3 DHParameter
   for 'ec:  param-bytes is ECPKParameters (RFC 3279)

|#

#|
;; Enumerate and describe all builtin elliptic curves.
;; Is there a standard, canonical name for curves?
;; Maybe NID => SN (short name) using OBJ_??? ?
(define curve-count (EC_get_builtin_curves #f 0))
(define ci0 (malloc curve-count _EC_builtin_curve 'atomic))
(set! ci0 (cast ci0 _pointer _EC_builtin_curve-pointer))
(EC_get_builtin_curves ci0 curve-count)
(for/list ([i curve-count])
  (define ci (ptr-add ci0 i _EC_builtin_curve))
  (list (EC_builtin_curve-nid ci) (EC_builtin_curve-comment ci)))
|#

;; ============================================================

(define libcrypto-read-key%
  (class* impl-base% (pk-read-key<%>)
    (inherit-field factory)
    (super-new)

    (define/public (read-key sk)
      (define-values (evp private?)
        (match sk
          ;; RSA, DSA private keys
          [(list 'pkcs1 'rsa 'private (? bytes? buf))
           (d2i_PrivateKey EVP_PKEY_RSA buf (bytes-length buf))]
          [(list 'libcrypto 'dsa 'private (? bytes? buf))
           (d2i_PrivateKey EVP_PKEY_DSA buf (bytes-length buf))]
          [(list 'pkcs8 (or 'rsa 'dsa) 'private (? bytes? buf)) ;; PrivateKeyInfo
           (let ([pkcs8info (d2i_PKCS8_PRIV_KEY_INFO buf (bytes-length buf))])
             (begin0 (EVP_PKCS82PKEY pkcs8info)
               (values (PKCS8_PRIV_KEY_INFO_free pkcs8info) #t)))]
          ;; RSA, DSA public keys (and maybe others too?)
          [(list 'pkix (or 'rsa 'dsa) 'public (? bytes? buf)) ;; SubjectPublicKeyInfo
           (values (d2i_PUBKEY buf (bytes-length buf)) #f)]
          [(list 'sec1 'ec 'private (? bytes? buf)) ;; ECPrivateKey
           (values (read-ec-key #t buf) #t)]
          [(list 'sec1 'ec 'public (? bytes? buf)) ;; ECPoint OCTET STRING
           (values (read-ec-key #f buf) #f)]
          [(list 'libcrypto 'dh 'public (? bytes? params) (? bytes? pub))
           (values (read-dh-key params pub #f) #f)]
          [(list 'libcrypto 'dh 'private (? bytes? params) (? bytes? pub) (? bytes? priv))
           (values (read-dh-key params pub priv) #t)]
          [_ #f]))
      (define impl (and evp (evp->impl evp)))
      (and evp impl (new libcrypto-pk-key% (impl impl) (evp evp) (private? private?))))

    (define/private (evp->impl evp)
      (define type (EVP->type evp))
      (define spec
        (cond [(assoc type type=>spec) => cdr]
              [else #f]))
      (and spec (send factory get-pk spec)))

    (define/private (read-dh-key params-buf pub-buf priv-buf)
      (define dh (d2i_DHparams params-buf (bytes-length params-buf)))
      ;; FIXME: DH check
      (when (or (DH_st_prefix-pubkey dh) (DH_st_prefix-privkey dh))
        (crypto-error "internal error; keys found in DH parameters object"))
      (let ([pubkey (BN_bin2bn pub-buf)])
        (set-DH_st_prefix-pubkey! dh pubkey)
        (BN-no-gc pubkey))
      (when priv-buf
        (let ([privkey (BN_bin2bn priv-buf)])
          (set-DH_st_prefix-privkey! dh privkey)
          (BN-no-gc privkey)))
      (define evp (EVP_PKEY_new))
      (EVP_PKEY_set1_DH evp dh)
      (DH_free dh)
      evp)

    (define/private (read-ec-key private? buf)
      (define ec
        (cond [private? (d2i_ECPrivateKey buf (bytes-length buf))]
              [else     (o2i_ECPublicKey buf (bytes-length buf))]))
      (define evp (EVP_PKEY_new))
      (EVP_PKEY_set1_EC_KEY evp ec)
      (EC_KEY_free ec)
      evp)

    (define/public (read-params sp)
      (define evp
        (match sp
          [(list 'libcrypto 'dsa (? bytes? buf))
           (define dsa (d2i_DSAparams buf (bytes-length buf)))
           (define evp (EVP_PKEY_new))
           (EVP_PKEY_set1_DSA evp dsa)
           (DSA_free dsa)
           evp]
          [(list 'libcrypto 'dh (? bytes? buf))
           (define dh (d2i_DHparams buf (bytes-length buf)))
           ;; FIXME: DH_check
           (define evp (EVP_PKEY_new))
           (EVP_PKEY_set1_DH evp dh)
           (DH_free dh)
           evp]
          [(list 'libcrypto 'ec (? bytes? buf))
           (define group (d2i_ECPKParameters buf (bytes-length buf)))
           ;; FIXME: check?
           (define ec (EC_KEY_new))
           (EC_KEY_set_group ec group)
           (EC_GROUP_free group)
           (define evp (EVP_PKEY_new))
           (EVP_PKEY_set1_EC_KEY evp ec)
           (EC_KEY_free ec)
           evp]))
      (define impl (and evp (evp->impl evp)))
      (new libcrypto-pk-params% (impl impl) (evp evp)))
    ))

;; ============================================================

(define libcrypto-pk-impl%
  (class* impl-base% (pk-impl<%>)
    (inherit-field spec)
    (super-new)

    (abstract pktype)

    (define/public (*write-key private? fmt evp)
      (cond [private?
             (case fmt
               [(pkcs8 #f)
                ;; FIXME: doesn't seem to work!
                ;; Writing RSA key gives only 3 non-NUL bytes at beginning.
                (define pkcs8info (EVP_PKEY2PKCS8 evp))
                `(pkcs8 ,spec private ,(i2d i2d_PKCS8_PRIV_KEY_INFO pkcs8info))]
               [else
                (crypto-error "key format not supported\n  format: ~e" fmt)])]
            [else ;; public
             (case fmt
               [(#f) ;; PUBKEY
                `(pkix ,spec public ,(i2d i2d_PUBKEY evp))]
               [else
                (crypto-error "key format not supported\n  format: ~e" fmt)])]))

    (define/public (generate-key config)
      (crypto-error "algorithm does not support direct key generation\n  algorithm: ~e" spec))
    (define/public (generate-params config)
      (crypto-error "algorithm does not support parameters\n  algorithm: ~e" spec))
    (define/public (can-encrypt?) #f)
    (define/public (can-sign?) #f)
    (define/public (can-key-agree?) #f)
    (define/public (has-params?) #f)
    ))

;; ============================================================

(define allowed-rsa-keygen
  `((nbits ,exact-positive-integer? "exact-positive-integer?")
    (e     ,exact-positive-integer? "exact-positive-integer?")))

(define libcrypto-rsa-impl%
  (class libcrypto-pk-impl%
    (super-new (spec 'rsa))

    (define/override (pktype) EVP_PKEY_RSA)
    (define/override (can-encrypt?) #t)
    (define/override (can-sign?) #t)

    (define/override (*write-key private? fmt evp)
      (cond [(and private? (memq fmt '(pkcs1 #f)))
             `(pkcs1 rsa private ,(i2d i2d_PrivateKey evp))]
            [else (super *write-key private? fmt evp)]))

    #|
    ;; Key generation currently fails, possibly due to something like the following
    ;; issue (but the suggested workaround doesn't work for me).
    ;;   [openssl.org #2244]
    ;;   https://groups.google.com/forum/#!topic/mailing.openssl.dev/jhooibXLmWk
    ;; Try using RSA_generate_key directly.
    (define/override (generate-key config)
      (check-keygen-spec config allowed-rsa-keygen)
      (let ([nbits (keygen-spec-ref config 'nbits)]
            [e (keygen-spec-ref config 'e)]
            [ctx (EVP_PKEY_CTX_new_id (pktype))])
        (EVP_PKEY_CTX_set_cb ctx #f)
        (EVP_PKEY_keygen_init ctx)
        (when nbits
          (EVP_PKEY_CTX_set_rsa_keygen_bits ctx nbits))
        (when e
          (let ([ebn (BN_new)])
            (BN_add_word ebn e)
            ;; FIXME: refcount?
            (EVP_PKEY_CTX_set_rsa_keygen_pubexp ctx ebn)
            #|(BN_free ebn)|#))
        (let ([evp (EVP_PKEY_keygen ctx)])
          (EVP_PKEY_CTX_free ctx)
          (new libcrypto-pk-key% (impl this) (evp evp) (private? #t)))))
    |#
    (define/override (generate-key config)
      (check-keygen-spec config allowed-rsa-keygen)
      (let ([nbits (or (keygen-spec-ref config 'nbits) 2048)]
            [e (or (keygen-spec-ref config 'e) 65537)])
        (define rsa (RSA_new))
        (define bn-e (BN_new))
        (BN_add_word bn-e e)
        (RSA_generate_key_ex rsa nbits bn-e #f)
        (define evp (EVP_PKEY_new))
        (EVP_PKEY_set1_RSA evp rsa)
        (RSA_free rsa)
        (new libcrypto-pk-key% (impl this) (evp evp) (private? #t))))

    (define/public (*set-sign-padding ctx pad)
      (EVP_PKEY_CTX_set_rsa_padding ctx
        (case pad
          [(pkcs1-v1.5) RSA_PKCS1_PADDING]
          [(pss #f)   RSA_PKCS1_PSS_PADDING]
          [else (crypto-error "bad RSA signing padding mode\n  padding: ~e" pad)])))

    (define/public (*set-encrypt-padding ctx pad)
      (EVP_PKEY_CTX_set_rsa_padding ctx
        (case pad
          [(pkcs1-v1.5) RSA_PKCS1_PADDING]
          [(oaep #f)  RSA_PKCS1_OAEP_PADDING]
          [else (crypto-error "bad RSA encryption padding mode\n  padding: ~e" pad)])))
    ))

;; ----

(define allowed-dsa-paramgen
  `((nbits ,exact-positive-integer? "exact-positive-integer?")))

(define libcrypto-dsa-impl%
  (class libcrypto-pk-impl%
    (inherit-field spec)
    (super-new (spec 'dsa))

    (define/override (pktype) EVP_PKEY_DSA)
    (define/override (can-sign?) #t)
    (define/override (has-params?) #t)

    (define/override (*write-key private? fmt evp)
      (cond [(and private? (memq fmt '(#f)))
             `(libcrypto dsa private ,(i2d i2d_PrivateKey evp))]
            [else (super *write-key private? fmt evp)]))

    (define/public (*write-params fmt evp)
      (unless (memq fmt '(#f libcrypto))
        (crypto-error "parameter format not supported\n  format: ~e" fmt))
      (define dsa (EVP_PKEY_get1_DSA evp))
      (define buf (make-bytes (i2d_DSAparams dsa #f)))
      (i2d_DSAparams dsa buf)
      (DSA_free dsa)
      `(libcrypto dsa ,buf))

    #|
    ;; Similarly, this version of generate-params crashes.
    (define/override (generate-params config)
      (check-keygen-spec 'generate-dsa-key config allowed-dsa-paramgen)
      (let ([nbits (keygen-spec-ref config 'nbits)]
            [ctx (EVP_PKEY_CTX_new_id (pktype))])
        (EVP_PKEY_paramgen_init ctx)
        (when nbits
          (EVP_PKEY_CTX_set_dsa_paramgen_bits ctx nbits))
        (let ([evp (EVP_PKEY_paramgen ctx)])
          (EVP_PKEY_CTX_free ctx)
          (new libcrypto-pk-params% (impl this) (evp evp)))))
    |#
    (define/override (generate-params config)
      (check-keygen-spec config allowed-dsa-paramgen)
      (let ([nbits (or (keygen-spec-ref config 'nbits) 1024)])
        (define dsa (DSA_new))
        (DSA_generate_parameters_ex dsa nbits)
        (define evp (EVP_PKEY_new))
        (EVP_PKEY_set1_DSA evp dsa)
        (DSA_free dsa)
        (new libcrypto-pk-params% (impl this) (evp evp))))

    ;; In contrast to other generate-{key,params} methods above, this use of
    ;; EVP_PKEY_keygen seems to work, but that may just be because DSA keygen
    ;; is simple after paramgen is done.
    (define/public (*generate-key config evp)
      (let ([ctx (EVP_PKEY_CTX_new evp)])
        (EVP_PKEY_keygen_init ctx)
        (let ([kevp (EVP_PKEY_keygen ctx)])
          (EVP_PKEY_CTX_free ctx)
          (new libcrypto-pk-key% (impl this) (evp kevp) (private? #t)))))

    (define/public (*set-sign-padding ctx pad)
      (case pad
        [(#f) (void)]
        [else (crypto-error "invalid padding argument for DSA\n  padding: ~e" pad)]))
    ))

;; ----

(define allowed-dh-paramgen
  `((nbits ,exact-positive-integer? "exact-positive-integer?")
    (generator ,(lambda (x) (member x '(2 5))) "(or/c 2 5)")))

(define libcrypto-dh-impl%
  (class libcrypto-pk-impl%
    (inherit-field spec)
    (super-new (spec 'dh))

    (define/override (pktype) EVP_PKEY_DH)
    (define/override (can-key-agree?) #t)
    (define/override (has-params?) #t)

    (define/override (generate-params config)
      (check-keygen-spec config allowed-dh-paramgen)
      (let ([nbits (keygen-spec-ref config 'nbits)]
            [generator (or (keygen-spec-ref config 'generator) 2)])
        (define dh (DH_new))
        (DH_generate_parameters_ex dh nbits generator)
        ;; FIXME: DH_check ???
        (define evp (EVP_PKEY_new))
        (EVP_PKEY_set1_DH evp dh)
        (DH_free dh)
        (new libcrypto-pk-params% (impl this) (evp evp))))

    (define/public (*write-params fmt evp)
      (unless (memq fmt '(#f libcrypto))
        (crypto-error "parameter format not supported\n  format: ~e" fmt))
      (define dh (EVP_PKEY_get1_DH evp))
      (define buf (make-bytes (i2d_DHparams dh #f)))
      (i2d_DHparams dh buf)
      (DH_free dh)
      `(libcrypto dh ,buf))

    (define/override (*write-key private? fmt evp)
      (unless (eq? fmt #f)
        (crypto-error "bad DH key format\n  format: ~e" fmt))
      (define dh (EVP_PKEY_get1_DH evp))
      (define pubkey-buf (BN->bytes/bin (DH_st_prefix-pubkey dh)))
      (define privkey-buf (and private? (BN->bytes/bin (DH_st_prefix-privkey dh))))
      (DH_free dh)
      (list* 'libcrypto 'dh (if private? 'private 'public)
             (caddr (*write-params fmt evp))
             pubkey-buf
             (if private? (list privkey-buf) null)))

    (define/public (*generate-key config evp)
      (define kdh
        (let ([dh0 (EVP_PKEY_get1_DH evp)])
          (begin0 (DHparams_dup dh0)
            (DH_free dh0))))
      (DH_generate_key kdh)
      (define kevp (EVP_PKEY_new))
      (EVP_PKEY_set1_DH kevp kdh)
      (DH_free kdh)
      (new libcrypto-pk-key% (impl this) (evp kevp) (private? #t)))

    (define/public (*convert-peer-pubkey evp peer-pubkey0)
      (define peer-dh
        (let ([dh0 (EVP_PKEY_get1_DH evp)])
          (begin0 (DHparams_dup dh0)
            (DH_free dh0))))
      (let ([pubkey (BN_bin2bn peer-pubkey0)])
        (set-DH_st_prefix-pubkey! peer-dh pubkey)
        (BN-no-gc pubkey))
      (define peer-evp (EVP_PKEY_new))
      (EVP_PKEY_set1_DH peer-evp peer-dh)
      (DH_free peer-dh)
      peer-evp)
    ))

;; ----

(define allowed-ec-paramgen
  `((curve-nid ,exact-nonnegative-integer? "exact-nonnegative-integer?")))

(define libcrypto-ec-impl%
  (class libcrypto-pk-impl%
    (inherit-field spec)
    (super-new (spec 'ec))

    (define/override (pktype) EVP_PKEY_EC)
    (define/override (can-sign?) #t)
    (define/override (can-key-agree?) #t)
    (define/override (has-params?) #t)

    (define/override (generate-params config)
      (check-keygen-spec config allowed-ec-paramgen)
      (let ([curve-nid (keygen-spec-ref config 'curve-nid)])
        (unless curve-nid
          (crypto-error "missing required configuration key\n  key: ~s" 'curve-nid))
        (define ec (EC_KEY_new_by_curve_name curve-nid))
        (unless ec
          (crypto-error "named curve not found\n  curve NID: ~e" curve-nid))
        (define evp (EVP_PKEY_new))
        (EVP_PKEY_set1_EC_KEY evp ec)
        (EC_KEY_free ec)
        (new libcrypto-pk-params% (impl this) (evp evp))))

    (define/public (*write-params fmt evp)
      (unless (memq fmt '(#f libcrypto))
        (crypto-error "parameter format not supported\n  format: ~e" fmt))
      (define ec (EVP_PKEY_get1_EC_KEY evp))
      (define group (EC_KEY_get0_group ec))
      (define len (i2d_ECPKParameters group #f))
      (define buf (make-bytes len))
      (define len2 (i2d_ECPKParameters group buf))
      (EC_KEY_free ec)
      `(libcrypto ec ,(shrink-bytes buf len2)))

    (define/override (*write-key private? fmt evp)
      (unless (memq fmt '(#f libcrypto))
        (crypto-error "key format not supported\n  format: ~e" fmt))
      (define ec (EVP_PKEY_get1_EC_KEY evp))
      (cond [private?
             (define outlen (i2d_ECPrivateKey ec #f))
             (define outbuf (make-bytes outlen))
             (define outlen2 (i2d_ECPrivateKey ec outbuf))
             (EC_KEY_free ec)
             `(sec1 ec private ,(shrink-bytes outbuf outlen2))]
            [else ;; public
             (define outlen (i2o_ECPublicKey ec #f))
             (define outbuf (make-bytes outlen))
             (define outlen2 (i2o_ECPublicKey ec outbuf))
             (EC_KEY_free ec)
             `(sec1 ec public ,(shrink-bytes outbuf outlen2))]))

    (define/public (*generate-key config evp)
      (define kec
        (let ([ec0 (EVP_PKEY_get1_EC_KEY evp)])
          (begin0 (EC_KEY_dup ec0)
            (EC_KEY_free ec0))))
      (EC_KEY_generate_key kec)
      (define kevp (EVP_PKEY_new))
      (EVP_PKEY_set1_EC_KEY kevp kec)
      (EC_KEY_free kec)
      (new libcrypto-pk-key% (impl this) (evp kevp) (private? #t)))

    (define/public (*convert-peer-pubkey evp peer-pubkey0)
      (define ec (EVP_PKEY_get1_EC_KEY evp))
      (define group (EC_KEY_get0_group ec))
      (define group-degree (EC_GROUP_get_degree group))
      (define buf (make-bytes (quotient (+ group-degree 7) 8)))
      (define peer-pubkey-point (EC_POINT_new group))
      (EC_POINT_oct2point group peer-pubkey-point peer-pubkey0 (bytes-length peer-pubkey0))
      (define peer-ec (EC_KEY_new))
      (EC_KEY_set_group peer-ec group)
      (EC_KEY_set_public_key peer-ec peer-pubkey-point)
      (EC_POINT_free peer-pubkey-point)
      (EC_KEY_free ec)
      (define peer-evp (EVP_PKEY_new))
      (EVP_PKEY_set1_EC_KEY peer-evp peer-ec)
      (EC_KEY_free peer-ec)
      peer-evp)

    (define/public (*set-sign-padding ctx pad)
      (case pad
        [(#f) (void)]
        [else (crypto-error "invalid padding argument for ECDSA\n  padding: ~e" pad)]))
    ))

;; ============================================================

(define allowed-params-keygen '())

(define libcrypto-pk-params%
  (class* ctx-base% (pk-params<%>)
    (init-field evp)
    (inherit-field impl)
    (super-new)

    ;; EVP_PKEY_keygen tends to crash, so call back to impl for low-level keygen.
    (define/public (generate-key config)
      (check-keygen-spec config allowed-params-keygen)
      (send impl *generate-key config evp))

    (define/public (write-params fmt)
      (send impl *write-params fmt evp))
    ))

;; ============================================================

(define libcrypto-pk-key%
  (class* ctx-base% (pk-key<%>)
    (init-field evp private?)
    (inherit-field impl)
    (super-new)

    (define/public (is-private?) private?)

    (define/public (get-public-key)
      (define outlen (i2d_PUBKEY evp #f))
      (define outbuf (make-bytes outlen))
      (define outlen2 (i2d_PUBKEY evp outbuf))
      (define pub-evp (d2i_PUBKEY outbuf outlen2))
      (new libcrypto-pk-key% (impl impl) (evp pub-evp) (private? #f)))

    (define/public (get-params)
      (let ([pevp (EVP_PKEY_new)])
        (EVP_PKEY_copy_parameters pevp evp)
        (new libcrypto-pk-params% (impl impl) (evp pevp))))

    (define/public (write-key fmt)
      (send impl *write-key private? fmt evp))

    (define/public (equal-to-key? other)
      (and (is-a? other libcrypto-pk-key%)
           (EVP_PKEY_cmp evp (get-field evp other))))

    (define/public (sign digest digest-spec pad)
      (unless (send impl can-sign?)
        (crypto-error "sign/verify not supported\n  algorithm: ~e" (send impl get-spec)))
      (unless private?
        (crypto-error "signing requires private key"))
      (define di (send (send impl get-factory) get-digest digest-spec))
      (unless (is-a? di libcrypto-digest-impl%)
        (crypto-error "could not get digest implementation\n  digest spec: ~e"
                      digest-spec))
      (define ctx (EVP_PKEY_CTX_new evp))
      (EVP_PKEY_sign_init ctx)
      (send impl *set-sign-padding ctx pad)
      (EVP_PKEY_CTX_set_signature_md ctx (get-field md di))
      (define siglen (EVP_PKEY_sign ctx #f 0 digest (bytes-length digest)))
      (define sigbuf (make-bytes siglen))
      (define siglen2 (EVP_PKEY_sign ctx sigbuf siglen digest (bytes-length digest)))
      (EVP_PKEY_CTX_free ctx)
      (shrink-bytes sigbuf siglen2))

    (define/public (verify digest digest-spec pad sig)
      (unless (send impl can-sign?)
        (crypto-error "sign/verify not supported\n  algorithm: ~e" (send impl get-spec)))
      (define di (send (send impl get-factory) get-digest digest-spec))
      (unless (is-a? di libcrypto-digest-impl%)
        (crypto-error "could not get digest implementation\n  digest spec: ~e"
                      digest-spec))
      (define ctx (EVP_PKEY_CTX_new evp))
      (EVP_PKEY_verify_init ctx)
      (send impl *set-sign-padding ctx pad)
      (EVP_PKEY_CTX_set_signature_md ctx (get-field md di))
      (begin0 (EVP_PKEY_verify ctx sig (bytes-length sig) digest (bytes-length digest))
        (EVP_PKEY_CTX_free ctx)))

    (define/public (encrypt buf pad)
      (unless (send impl can-encrypt?)
        (crypto-error "encrypt/decrypt not supported\n  algorithm: ~e" (send impl get-spec)))
      (*crypt buf pad EVP_PKEY_encrypt_init EVP_PKEY_encrypt))

    (define/public (decrypt buf pad)
      (unless (send impl can-encrypt?)
        (crypto-error "encrypt/decrypt not supported\n  algorithm: ~e" (send impl get-spec)))
      (unless private? (crypto-error "decryption requires private key"))
      (*crypt buf pad EVP_PKEY_decrypt_init EVP_PKEY_decrypt))

    (define/private (*crypt buf pad EVP_*crypt_init EVP_*crypt)
      (define ctx (EVP_PKEY_CTX_new evp))
      (EVP_*crypt_init ctx)
      (send impl *set-encrypt-padding ctx pad)
      (define outlen (EVP_*crypt ctx #f 0 buf (bytes-length buf)))
      (define outbuf (make-bytes outlen))
      (define outlen2 (EVP_*crypt ctx outbuf outlen buf (bytes-length buf)))
      (EVP_PKEY_CTX_free ctx)
      (shrink-bytes outbuf outlen2))

    (define/public (compute-secret peer-pubkey0)
      (unless (send impl can-key-agree?)
        (crypto-error "key agreement not supported\n  algorithm: ~e" (send impl get-spec)))
      (define peer-pubkey
        (cond [(and (is-a? peer-pubkey0 libcrypto-pk-key%)
                    (eq? (send peer-pubkey0 get-impl) impl))
               (get-field evp peer-pubkey0)]
              [else (send impl *convert-peer-pubkey evp peer-pubkey0)]))
      (define ctx (EVP_PKEY_CTX_new evp))
      (EVP_PKEY_derive_init ctx)
      (EVP_PKEY_derive_set_peer ctx peer-pubkey)
      (define outlen (EVP_PKEY_derive ctx #f 0))
      (define buf (make-bytes outlen))
      (define outlen2 (EVP_PKEY_derive ctx buf (bytes-length buf)))
      (shrink-bytes buf outlen2))
    ))
