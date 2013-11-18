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

References:
 - https://groups.google.com/forum/#!topic/mailing.openssl.users/HsiN-8Lt0H8
 - http://openssl.6102.n7.nabble.com/difference-between-i2d-PUBKEY-and-i2d-PublicKey-td43869.html
 - http://www.openssl.org/docs/crypto/pem.html

Generating keys & params for testing:

  openssl genrsa -out rsa-512.key 512
  openssl rsa -inform pem -outform der -in rsa-512.key -out rsa-512.der
  (bytes->private-key rsai (file->bytes "rsa-512.der"))

  openssl dsaparam -outform pem -out dsa-512.params 512
  openssl gendsa -out dsa-512.key dsa-512.params
  openssl dsa -inform pem -outform der -in dsa-512.key -out dsa-512.der
  (bytes->private-key dsai (file->bytes "dsa-512.der"))

|#

(define libcrypto-pkey-impl%
  (class* impl-base% (pkey-impl<%>)
    (super-new)

    (define/public (read-key who buf pub/priv fmt)
      (unless (eq? fmt #f)
        (error who "key format not supported\n  format: ~e" fmt))
      (let ([evp
             (case pub/priv
               [(private) (d2i_PrivateKey (pktype) buf (bytes-length buf))]
               [(public) (d2i_PublicKey (pktype) buf (bytes-length buf))])])
        (new libcrypto-pkey-key% (impl this) (evp evp) (private? (eq? pub/priv 'private)))))

    (abstract pktype)
    (abstract read-params)
    (abstract generate-params)
    (abstract generate-key)
    (abstract can-encrypt?)
    (define/public (can-sign?) #t)
    ))

(define allowed-rsa-keygen
  `((nbits ,exact-positive-integer? "exact-positive-integer?")
    (e     ,exact-positive-integer? "exact-positive-integer?")))

(define libcrypto-rsa-impl%
  (class libcrypto-pkey-impl%
    (super-new)
    (define/override (pktype) EVP_PKEY_RSA)
    (define/override (can-encrypt?) #t)
    (define/override (read-params who buf fmt)
      (error who "reading parameters not supported"))
    (define/public (*write-params who evp)
      (error who "internal error; writing parameters not supported"))
    (define/override (generate-params who config)
      (error who "parameter generation not supported"))
    #|
    ;; Key generation currently fails, possibly due to something like the following
    ;; issue (but the suggested workaround doesn't work for me).
    ;;   [openssl.org #2244]
    ;;   https://groups.google.com/forum/#!topic/mailing.openssl.dev/jhooibXLmWk
    ;; Try using RSA_generate_key directly.
    (define/override (generate-key who config)
      (check-keygen-spec who config allowed-rsa-keygen)
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
          (new libcrypto-pkey-key% (impl this) (evp evp) (private? #t)))))
    |#
    (define/override (generate-key who config)
      (check-keygen-spec who config allowed-rsa-keygen)
      (let ([nbits (or (keygen-spec-ref config 'nbits) 2048)]
            [e (or (keygen-spec-ref config 'e) 65537)])
        (define rsa (RSA_new))
        (define bn-e (BN_new))
        (BN_add_word bn-e e)
        (RSA_generate_key_ex rsa nbits bn-e #f)
        (define evp (EVP_PKEY_new))
        (EVP_PKEY_set1_RSA evp rsa)
        (RSA_free rsa)
        (new libcrypto-pkey-key% (impl this) (evp evp) (private? #t))))
    (define/public (*set-sign-padding who ctx pad)
      (EVP_PKEY_CTX_set_rsa_padding ctx
        (case pad
          [(pkcs1) RSA_PKCS1_PADDING]
          [(pss #f)   RSA_PKCS1_PSS_PADDING]
          [else (error who "bad RSA signing padding mode\n  padding: ~e" pad)])))
    (define/public (*set-encrypt-padding who ctx pad)
      (EVP_PKEY_CTX_set_rsa_padding ctx
        (case pad
          [(pkcs1) RSA_PKCS1_PADDING]
          [(oaep #f)  RSA_PKCS1_OAEP_PADDING]
          [else (error who "bad RSA encryption padding mode\n  padding: ~e" pad)])))
    ))

(define allowed-dsa-paramgen
  `((nbits ,exact-positive-integer? "exact-positive-integer?")))

(define libcrypto-dsa-impl%
  (class libcrypto-pkey-impl%
    (super-new)
    (define/override (pktype) EVP_PKEY_DSA)
    (define/override (can-encrypt?) #f)
    (define/override (read-params who buf fmt)
      (unless (eq? fmt #f)
        (error who "parameter format not supported\n  format: ~e" fmt))
      (let ([dsa (d2i_DSAparams buf (bytes-length buf))]
            [evp (EVP_PKEY_new)])
        (EVP_PKEY_set1_DSA evp dsa)
        (DSA_free dsa)
        (new libcrypto-pkey-params% (impl this) (evp evp))))
    (define/public (*write-params who evp)
      (let* ([dsa (EVP_PKEY_get1_DSA evp)]
             [buf (make-bytes (i2d_DSAparams dsa #f))])
        (i2d_DSAparams dsa buf)
        (DSA_free dsa)
        buf))
    (define/override (generate-key who config)
      (error who "direct key generation not supported;\n generate key from parameters"))
    #|
    ;; Similarly, this version of generate-params crashes.
    (define/override (generate-params who config)
      (check-keygen-spec 'generate-dsa-key config allowed-dsa-paramgen)
      (let ([nbits (keygen-spec-ref config 'nbits)]
            [ctx (EVP_PKEY_CTX_new_id (pktype))])
        (EVP_PKEY_paramgen_init ctx)
        (when nbits
          (EVP_PKEY_CTX_set_dsa_paramgen_bits ctx nbits))
        (let ([evp (EVP_PKEY_paramgen ctx)])
          (EVP_PKEY_CTX_free ctx)
          (new libcrypto-pkey-params% (impl this) (evp evp)))))
    |#
    (define/override (generate-params who config)
      (check-keygen-spec who config allowed-dsa-paramgen)
      (let ([nbits (or (keygen-spec-ref config 'nbits) 1024)])
        (define dsa (DSA_new))
        (DSA_generate_parameters_ex dsa nbits)
        (define evp (EVP_PKEY_new))
        (EVP_PKEY_set1_DSA evp dsa)
        (DSA_free dsa)
        (new libcrypto-pkey-params% (impl this) (evp evp))))
    (define/public (*set-sign-padding who ctx pad)
      (case pad
        [(#f) (void)]
        [else (error who "invalid padding argument for DSA\n  padding: ~e" pad)]))
    ))

(define allowed-dsa-keygen '())

(define libcrypto-pkey-params%
  (class* ctx-base% (pkey-params<%>)
    (init-field evp)
    (inherit-field impl)
    (super-new)

    ;; In contrast to the generate-{key,params} methods above, this use of
    ;; EVP_PKEY_keygen seems to work, but that may be because DSA keygen is
    ;; simple after paramgen is done.
    (define/public (generate-key who config)
      (check-keygen-spec who config allowed-dsa-keygen)
      (let ([ctx (EVP_PKEY_CTX_new evp)])
        (EVP_PKEY_keygen_init ctx)
        (let ([kevp (EVP_PKEY_keygen ctx)])
          (EVP_PKEY_CTX_free ctx)
          (new libcrypto-pkey-key% (impl impl) (evp kevp) (private? #t)))))

    (define/public (write-params who fmt)
      (unless (eq? fmt #f)
        (error who "parameter format not supported\n  format: ~e" fmt))
      (send impl *write-params who evp))
    ))

(define libcrypto-pkey-key%
  (class* ctx-base% (pkey-key<%>)
    (init-field evp private?)
    (inherit-field impl)
    (super-new)

    (define/public (is-private?) private?)

    (define/public (get-public-key who)
      (let ([pub (write-key 'get-public-key 'public #f)])
        (let ([pubevp (d2i_PublicKey (send impl pktype) pub (bytes-length pub))])
          (new libcrypto-pkey-key% (impl impl) (evp evp) (private? #f)))))

    (define/public (get-params who)
      (let ([pevp (EVP_PKEY_new)])
        (EVP_PKEY_copy_parameters pevp evp)
        (new libcrypto-pkey-params% (impl impl) (evp pevp))))

    (define/public (write-key who pub/priv fmt)
      (unless (eq? fmt #f)
        (error who "key format not supported\n  format: ~e" fmt))
      (let* ([i2d (case pub/priv
                    [(public) i2d_PublicKey]
                    [(private) i2d_PrivateKey])]
             [buf (make-bytes (i2d evp #f))])
        (i2d evp buf)
        buf))

    (define/public (equal-to-key? other)
      (and (is-a? other libcrypto-pkey-key%)
           (EVP_PKEY_cmp evp (get-field evp other))))

    ;; From headers, EVP_{Sign,Verify}{Init_ex,Update} are just macros for
    ;; EVP_Digest{Init_ex,Update}. So digest state is compatible.

    (define/public (sign who digest digest-spec pad)
      (unless private? (error who "signing requires private key"))
      (define di (send (send impl get-factory) get-digest digest-spec))
      (unless (is-a? di libcrypto-digest-impl%)
        (error who "could not get digest implementation\n  digest spec: ~e"
               digest-spec))
      (define ctx (EVP_PKEY_CTX_new evp))
      (EVP_PKEY_sign_init ctx)
      (send impl *set-sign-padding who ctx pad)
      (EVP_PKEY_CTX_set_signature_md ctx (get-field md di))
      (define siglen (EVP_PKEY_sign ctx #f 0 digest (bytes-length digest)))
      (define sigbuf (make-bytes siglen))
      (define siglen2 (EVP_PKEY_sign ctx sigbuf siglen digest (bytes-length digest)))
      (EVP_PKEY_CTX_free ctx)
      (shrink-bytes sigbuf siglen2))

    (define/public (verify who digest digest-spec pad sig)
      (define di (send (send impl get-factory) get-digest digest-spec))
      (unless (is-a? di libcrypto-digest-impl%)
        (error who "could not get digest implementation\n  digest spec: ~e"
               digest-spec))
      (define ctx (EVP_PKEY_CTX_new evp))
      (EVP_PKEY_verify_init ctx)
      (send impl *set-sign-padding who ctx pad)
      (EVP_PKEY_CTX_set_signature_md ctx (get-field md di))
      (begin0 (EVP_PKEY_verify ctx sig (bytes-length sig) digest (bytes-length digest))
        (EVP_PKEY_CTX_free ctx)))

    (define/public (encrypt who buf pad)
      (*crypt who buf pad EVP_PKEY_encrypt_init EVP_PKEY_encrypt))

    (define/public (decrypt who buf pad)
      (unless private? (error who "decryption requires private key"))
      (*crypt who buf pad EVP_PKEY_decrypt_init EVP_PKEY_decrypt))

    (define/private (*crypt who buf pad EVP_*crypt_init EVP_*crypt)
      (define ctx (EVP_PKEY_CTX_new evp))
      (EVP_*crypt_init ctx)
      (send impl *set-encrypt-padding who ctx pad)
      (define outlen (EVP_*crypt ctx #f 0 buf (bytes-length buf)))
      (define outbuf (make-bytes outlen))
      (define outlen2 (EVP_*crypt ctx outbuf outlen buf (bytes-length buf)))
      (EVP_PKEY_CTX_free ctx)
      (shrink-bytes outbuf outlen2))
    ))
