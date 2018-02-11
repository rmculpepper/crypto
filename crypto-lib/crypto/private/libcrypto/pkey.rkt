;; Copyright 2012-2014 Ryan Culpepper
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
         asn1
         "../rkt/pk-asn1.rkt"
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/error.rkt"
         "ffi.rkt"
         "digest.rkt")
(provide (all-defined-out))

#|
TODO: check params (eg safe primes) on generate-params OR read-params

KNOWN BUG: Curve prime256v1 (NID=415) doesn't work with key derivation
in OpenSSL 1.0.1c (Ubuntu 12.10), fixed in 1.0.1e (Fedora 20) (but
NIST P-192 disappeared!).
|#

;; ============================================================

(define libcrypto-read-key%
  (class* impl-base% (pk-read-key<%>)
    (inherit-field factory)
    (super-new (spec 'libcrypto-read-key))

    (define/public (read-key sk fmt)
      (define (check-bytes)
        (unless (bytes? sk)
          (crypto-error "bad value for key format\n  format: ~e\n  expected: ~s\n  got: ~e"
                        fmt 'bytes? sk)))
      (define-values (evp private?)
        (case fmt
          [(SubjectPublicKeyInfo)
           (check-bytes)
           (values (d2i_PUBKEY sk (bytes-length sk)) #f)]
          [(PrivateKeyInfo)
           (check-bytes)
           (define p8 (d2i_PKCS8_PRIV_KEY_INFO sk (bytes-length sk)))
           (values (and p8 (EVP_PKCS82PKEY p8)) #t)]
          [(RSAPrivateKey)
           (check-bytes)
           (values (d2i_PrivateKey EVP_PKEY_RSA sk (bytes-length sk)) #t)]
          [(DSAPrivateKey)
           (check-bytes)
           (values (d2i_PrivateKey EVP_PKEY_DSA sk (bytes-length sk)) #t)]
          [(ECPrivateKey)
           (check-bytes)
           (values (read-private-ec-key sk) #t)]
          [else (values #f #f)]))
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
        (internal-error "keys found in DH parameters object"))
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

    (define/private (read-private-ec-key buf)
      (define ec (d2i_ECPrivateKey buf (bytes-length buf)))
      (define evp (EVP_PKEY_new))
      (EVP_PKEY_set1_EC_KEY evp ec)
      (EC_KEY_free ec)
      evp)

    (define/public (read-params buf fmt)
      (define (evp->params evp)
        (define impl (and evp (evp->impl evp)))
        (and impl (new libcrypto-pk-params% (impl impl) (evp evp))))
      (case fmt
        [(AlgorithmIdentifier)
         (match (bytes->asn1/DER AlgorithmIdentifier/DER buf)
           [(hash-table ['algorithm alg-oid] ['parameters parameters])
            (cond [(equal? alg-oid id-dsa)
                   (read-params parameters 'DSAParameters)] ;; Dss-Parms
                  [(equal? alg-oid dhKeyAgreement)
                   (read-params parameters 'DHParameter)] ;; DHParameter
                  [(equal? alg-oid id-ecPublicKey)
                   (read-params parameters 'EcpkParameters)] ;; PcpkParameters
                  [else #f])]
           [_ #f])]
        [(DSAParameters)
         (define dsa (d2i_DSAparams buf (bytes-length buf)))
         (define evp (EVP_PKEY_new))
         (EVP_PKEY_set1_DSA evp dsa)
         (DSA_free dsa)
         (evp->params evp)]
        [(DHParameter) ;; PKCS#3 ... not DomainParameters!
         (define dh (d2i_DHparams buf (bytes-length buf)))
         ;; FIXME: DH_check
         (define evp (EVP_PKEY_new))
         (EVP_PKEY_set1_DH evp dh)
         (DH_free dh)
         (evp->params evp)]
        [(EcpkParameters)
         (define group (d2i_ECPKParameters buf (bytes-length buf)))
         ;; FIXME: check?
         (define ec (EC_KEY_new))
         (EC_KEY_set_group ec group)
         (EC_GROUP_free group)
         (define evp (EVP_PKEY_new))
         (EVP_PKEY_set1_EC_KEY evp ec)
         (EC_KEY_free ec)
         (evp->params evp)]
        [else #f]))
    ))

;; ============================================================

(define libcrypto-pk-impl%
  (class pk-impl-base%
    (inherit-field spec factory)
    (super-new)

    (abstract pktype)

    (define/public (*write-key private? fmt evp)
      (case fmt
        [(SubjectPublicKeyInfo)
         (i2d i2d_PUBKEY evp)]
        [(PrivateKeyInfo)
         (cond [private?
                (define p8 (EVP_PKEY2PKCS8 evp))
                (i2d i2d_PKCS8_PRIV_KEY_INFO p8)]
               [else #f])]
        [else #f]))

    (define/public (-known-digest? dspec)
      (or (not dspec) (and (send factory get-digest dspec) #t)))
    ))

;; ============================================================

(define allowed-rsa-keygen
  `((nbits ,exact-positive-integer? "exact-positive-integer?")
    (e     ,exact-positive-integer? "exact-positive-integer?")))

(define libcrypto-rsa-impl%
  (class libcrypto-pk-impl%
    (inherit-field spec)
    (inherit -known-digest?)
    (super-new (spec 'rsa))

    (define/override (pktype) EVP_PKEY_RSA)
    (define/override (can-encrypt? pad) (memq pad '(#f pkcs1-v1.5 oaep)))
    (define/override (can-sign? pad dspec) ;; FIXME: check digest compat
      (and (memq pad '(#f pkcs1-v1.5 pss pss*)) (-known-digest? dspec)))

    (define/override (*write-key private? fmt evp)
      (cond [(and (eq? fmt 'RSAPrivateKey) private?)
             (i2d i2d_PrivateKey evp)]
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

    (define/public (*set-sign-padding ctx pad saltlen sign?)
      (case pad
        [(pkcs1-v1.5 #f)
         (EVP_PKEY_CTX_set_rsa_padding ctx RSA_PKCS1_PADDING)]
        [(pss)
         (EVP_PKEY_CTX_set_rsa_padding ctx RSA_PKCS1_PSS_PADDING)
         (when saltlen (EVP_PKEY_CTX_set_rsa_pss_saltlen ctx saltlen))]
        [(pss*)
         (EVP_PKEY_CTX_set_rsa_padding ctx RSA_PKCS1_PSS_PADDING)
         (when sign? (EVP_PKEY_CTX_set_rsa_pss_saltlen ctx saltlen))]
        [else (err/bad-signature-pad this pad)]))

    (define/public (*set-encrypt-padding ctx pad)
      (EVP_PKEY_CTX_set_rsa_padding ctx
        (case pad
          [(pkcs1-v1.5) RSA_PKCS1_PADDING]
          [(oaep #f)  RSA_PKCS1_OAEP_PADDING]
          [else (err/bad-encrypt-pad this pad)])))
    ))

;; ----

(define allowed-dsa-paramgen
  `((nbits ,exact-positive-integer? "exact-positive-integer?")))

(define libcrypto-dsa-impl%
  (class libcrypto-pk-impl%
    (inherit-field spec)
    (inherit -known-digest?)
    (super-new (spec 'dsa))

    (define/override (pktype) EVP_PKEY_DSA)
    (define/override (can-sign? pad dspec)
      (and (memq pad '(#f)) (-known-digest? dspec)))
    (define/override (has-params?) #t)

    (define/override (*write-key private? fmt evp)
      (cond [(and (eq? fmt 'DSAPrivateKey) private?)
             (i2d i2d_PrivateKey evp)]
            [else (super *write-key private? fmt evp)]))

    (define/public (*write-params fmt evp)
      (case fmt
        [(AlgorithmIdentifier)
         (asn1->bytes/DER AlgorithmIdentifier/DER
          (hasheq 'algorithm id-dsa
                  'parameters (*write-params 'DSAParameters evp)))]
        [(DSAParameters)
         (define dsa (EVP_PKEY_get1_DSA evp))
         (define buf (make-bytes (i2d_DSAparams dsa #f)))
         (i2d_DSAparams dsa buf)
         (DSA_free dsa)
         buf]
        [else #f]))

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
      (let ([nbits (or (keygen-spec-ref config 'nbits) 2048)])
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

    (define/public (*set-sign-padding ctx pad saltlen sign?)
      (case pad
        [(#f) (void)]
        [else (err/bad-signature-pad this pad)]))
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
      (case fmt
        [(AlgorithmIdentifier)
         (asn1->bytes/DER AlgorithmIdentifier/DER
          (hasheq 'algorithm dhKeyAgreement
                  'parameters (*write-params 'DHParameter evp)))]
        [(DHParameter)
         (define dh (EVP_PKEY_get1_DH evp))
         (define buf (make-bytes (i2d_DHparams dh #f)))
         (i2d_DHparams dh buf)
         (DH_free dh)
         buf]
        [else #f]))

    (define/override (*write-key private? fmt evp)
      (super *write-key private? fmt evp))

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
  `((curve ,string? "string?")))

(define libcrypto-ec-impl%
  (class libcrypto-pk-impl%
    (inherit-field spec)
    (inherit -known-digest?)
    (super-new (spec 'ec))

    (define/override (pktype) EVP_PKEY_EC)
    (define/override (can-sign? pad dspec)
      (and (memq pad '(#f)) (-known-digest? dspec)))
    (define/override (can-key-agree?) #t)
    (define/override (has-params?) #t)

    (define/override (generate-params config)
      (check-keygen-spec config allowed-ec-paramgen)
      (define curve-name (keygen-spec-ref config 'curve))
      (unless curve-name (crypto-error "missing required configuration key\n  key: ~s" 'curve))
      (define curve-nid (find-curve-nid-by-name curve-name))
      (unless curve-nid (crypto-error "named curve not found\n  curve: ~e" curve-name))
      (define ec (EC_KEY_new_by_curve_name curve-nid))
      (unless ec (crypto-error "named curve not found\n  curve: ~e" curve-name))
      (begin
        ;; See http://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman
        ;; in section "ECDH and Named Curves"
        ;; FIXME: when/if curves other than named curves get supported, update
        (EC_KEY_set_asn1_flag ec OPENSSL_EC_NAMED_CURVE))
      (define evp (EVP_PKEY_new))
      (EVP_PKEY_set1_EC_KEY evp ec)
      (EC_KEY_free ec)
      (new libcrypto-pk-params% (impl this) (evp evp)))

    (define/public (*write-params fmt evp)
      (case fmt
        [(AlgorithmIdentifier)
         (asn1->bytes/DER AlgorithmIdentifier/DER
          (hasheq 'algorithm id-ecPublicKey
                  'parameters (*write-params 'EcpkParameters evp)))]
        [(EcpkParameters)
         (define ec (EVP_PKEY_get1_EC_KEY evp))
         (define group (EC_KEY_get0_group ec))
         (define len (i2d_ECPKParameters group #f))
         (define buf (make-bytes len))
         (define len2 (i2d_ECPKParameters group buf))
         (EC_KEY_free ec)
         (shrink-bytes buf len2)]
        [else #f]))

    (define/override (*write-key private? fmt evp)
      (cond [(and (eq? fmt 'ECPrivateKey) private?)
             (define ec (EVP_PKEY_get1_EC_KEY evp))
             (define outlen (i2d_ECPrivateKey ec #f))
             (define outbuf (make-bytes outlen))
             (define outlen2 (i2d_ECPrivateKey ec outbuf))
             (EC_KEY_free ec)
             (shrink-bytes outbuf outlen2)]
            [else (super *write-key private? fmt evp)]))

    (define/public (*generate-key config evp)
      (define kec
        (let ([ec0 (EVP_PKEY_get1_EC_KEY evp)])
          (begin0 (EC_KEY_dup ec0)
            (EC_KEY_free ec0))))
      (EC_KEY_generate_key kec)
      (begin
        ;; See note in generate-params above.
        (EC_KEY_set_asn1_flag kec OPENSSL_EC_NAMED_CURVE))
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

    (define/public (*set-sign-padding ctx pad saltlen sign?)
      (case pad
        [(#f) (void)]
        [else (err/bad-signature-pad this pad)]))
    ))

;; ============================================================

(define allowed-params-keygen '())

(define libcrypto-pk-params%
  (class pk-params-base%
    (init-field evp)
    (inherit-field impl)
    (super-new)

    ;; EVP_PKEY_keygen tends to crash, so call back to impl for low-level keygen.
    (define/override (generate-key config)
      (check-keygen-spec config allowed-params-keygen)
      (send impl *generate-key config evp))

    (define/override (-write-params fmt)
      (send impl *write-params fmt evp))
    ))

;; ============================================================

(define libcrypto-pk-key%
  (class pk-key-base%
    (init-field evp private?)
    (inherit-field impl)
    (super-new)

    (define/override (is-private?) private?)

    (define/override (get-public-key)
      (define outlen (i2d_PUBKEY evp #f))
      (define outbuf (make-bytes outlen))
      (define outlen2 (i2d_PUBKEY evp outbuf))
      (define pub-evp (d2i_PUBKEY outbuf outlen2))
      (new libcrypto-pk-key% (impl impl) (evp pub-evp) (private? #f)))

    (define/override (get-params)
      ;; Note: EVP_PKEY_copy_parameters doesn't work! (Probably used
      ;; to copy params from cert to key).  We treat keys as read-only
      ;; once created, so safe to share evp.
      (new libcrypto-pk-params% (impl impl) (evp evp)))

    (define/override (write-key fmt)
      (send impl *write-key private? fmt evp))

    (define/override (equal-to-key? other)
      (and (is-a? other libcrypto-pk-key%)
           (EVP_PKEY_cmp evp (get-field evp other))))

    (define/override (-sign digest digest-spec pad)
      (define di (send (send impl get-factory) get-digest digest-spec))
      (unless (is-a? di libcrypto-digest-impl%) (err/missing-digest digest-spec))
      (define ctx (EVP_PKEY_CTX_new evp))
      (EVP_PKEY_sign_init ctx)
      (send impl *set-sign-padding ctx pad (send di get-size) #t)
      (EVP_PKEY_CTX_set_signature_md ctx (get-field md di))
      (define siglen (EVP_PKEY_sign ctx #f 0 digest (bytes-length digest)))
      (define sigbuf (make-bytes siglen))
      (define siglen2 (EVP_PKEY_sign ctx sigbuf siglen digest (bytes-length digest)))
      (EVP_PKEY_CTX_free ctx)
      (shrink-bytes sigbuf siglen2))

    (define/override (-verify digest digest-spec pad sig)
      (define di (send (send impl get-factory) get-digest digest-spec))
      (unless (is-a? di libcrypto-digest-impl%) (err/missing-digest digest-spec))
      (define ctx (EVP_PKEY_CTX_new evp))
      (EVP_PKEY_verify_init ctx)
      (send impl *set-sign-padding ctx pad (send di get-size) #f)
      (EVP_PKEY_CTX_set_signature_md ctx (get-field md di))
      (begin0 (EVP_PKEY_verify ctx sig (bytes-length sig) digest (bytes-length digest))
        (EVP_PKEY_CTX_free ctx)))

    (define/override (-encrypt buf pad)
      (*crypt buf pad EVP_PKEY_encrypt_init EVP_PKEY_encrypt))

    (define/override (-decrypt buf pad)
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

    (define/override (-compute-secret peer-pubkey0)
      (define peer-pubkey
        (cond [(bytes? peer-pubkey0)
               (send impl *convert-peer-pubkey evp peer-pubkey0)]
              [(and (is-a? peer-pubkey0 libcrypto-pk-key%)
                    (eq? (send peer-pubkey0 get-impl) impl))
               (get-field evp peer-pubkey0)]
              [else (internal-error "bad peer public key")]))
      (define ctx (EVP_PKEY_CTX_new evp))
      (EVP_PKEY_derive_init ctx)
      (EVP_PKEY_derive_set_peer ctx peer-pubkey)
      (define outlen (EVP_PKEY_derive ctx #f 0))
      (define buf (make-bytes outlen))
      (define outlen2 (EVP_PKEY_derive ctx buf (bytes-length buf)))
      (shrink-bytes buf outlen2))
    ))

;; ============================================================

;; get-builtin-curve-nids : -> (listof Nat)
(define builtin-curve-nids #f)
(define (get-builtin-curve-nids)
  (unless builtin-curve-nids
    (set! builtin-curve-nids (map car (enumerate-builtin-curves))))
  builtin-curve-nids)

;; Enumerate and describe all builtin elliptic curves.
(define (enumerate-builtin-curves)
  (define curve-count (EC_get_builtin_curves #f 0))
  (define ci0 (malloc curve-count _EC_builtin_curve 'atomic))
  (set! ci0 (cast ci0 _pointer _EC_builtin_curve-pointer))
  (EC_get_builtin_curves ci0 curve-count)
  (for/list ([i curve-count])
    (define ci (ptr-add ci0 i _EC_builtin_curve))
    (define nid (EC_builtin_curve-nid ci))
    (list nid
          (EC_builtin_curve-comment ci)
          (OBJ_nid2sn nid))))

;; find-curve-nid-by-sn : String -> Nat/#f
(define (find-curve-nid-by-sn sn)
  (define nid (OBJ_sn2nid sn))
  (and (member nid (get-builtin-curve-nids)) nid))

;; Note about curve names and aliases:
;;   http://tools.ietf.org/html/rfc4492#section-5.1.1
;;   http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
;;   https://bugs.launchpad.net/pyopenssl/+bug/1233810

;; find-curve-nid-by-name : String -> Nat/#f
(define (find-curve-nid-by-name name)
  (or (find-curve-nid-by-sn name)
      (for/or ([alias-set (in-list curve-aliases)]
               #:when (member name alias-set))
        (for/or ([alias (in-list alias-set)])
          (find-curve-nid-by-sn alias)))))

(define curve-aliases
  ;; Source: RFC4492
  ;; [ SEC2/RFC4492 | NIST FIPS 186-4 | ANSI X9.62 ]
  '(["sect163k1" "NIST K-163"]
    ["sect163r1"]
    ["sect163r2" "NIST B-163"]
    ["sect193r1"]
    ["sect193r2"]
    ["sect233k1" "NIST K-233"]
    ["sect233r1" "NIST B-233"]
    ["sect239k1"]
    ["sect283k1" "NIST K-283"]
    ["sect283r1" "NIST B-283"]
    ["sect409k1" "NIST K-409"]
    ["sect409r1" "NIST B-409"]
    ["sect571k1" "NIST K-571"]
    ["sect571r1" "NIST B-571"]
    ["secp160k1"]
    ["secp160r1"]
    ["secp160r2"]
    ["secp192k1"]
    ["secp192r1" "NIST P-192" "prime192v1"]
    ["secp224k1"]
    ["secp224r1" "NIST P-224"]
    ["secp256k1"]
    ["secp256r1" "NIST P-256" "prime256v1"]
    ["secp384r1" "NIST P-384"]
    ["secp521r1" "NIST P-521"]))
