;; Copyright 2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/class
         racket/match
         "../common/common.rkt"
         "../common/kdf.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide libcrypto3-kdf-impl%)

(define libcrypto3-kdf-impl%
  (class kdf-impl-base%
    (inherit about)
    (init-field evp salt? params0)
    (inherit-field spec)
    (super-new)

    (define/override (kdf config pass salt)
      (define-values (key-size params1)
        (match spec
          [(or 'argon2d 'argon2i 'argon2id)
           ;; params0 is empty
           (define-values (t m p v key-size)
             (check/ref-config '(t m p v key-size) config config:argon2-kdf "Argon2"))
           (values key-size
                   `((#"pass" octet-string ,pass)
                     (#"salt" octet-string ,salt)
                     (#"iter" uint ,t)
                     (#"memcost" uint ,m)
                     (#"lanes" uint ,p)
                     (#"version" uint ,v)))]
          [(list 'pbkdf2 'hmac _)
           ;; params0 contains "digest"
           (define-values (iters key-size)
             (check/ref-config '(iterations key-size) config config:pbkdf2-kdf "PBKDF2"))
           (values key-size
                   `((#"pass" octet-string ,pass)
                     (#"salt" octet-string ,salt)
                     (#"iter" uint ,iters)))]
          ['scrypt
           ;; params0 is empty
           (define-values (N ln p r key-size)
             (check/ref-config '(N ln p r key-size) config config:scrypt-kdf "scrypt"))
           (values key-size
                   `((#"pass" octet-string ,pass)
                     (#"salt" octet-string ,salt)
                     (#"n" ulong ,(or N (expt 2 ln)))
                     (#"r" uint ,r)
                     (#"p" uint ,p)))]
          [(list 'hkdf _)
           ;; params0 contains "digest"
           (define-values (info key-size)
             (check/ref-config '(info key-size) config config:info-kdf "HKDF"))
           (values key-size
                   `((#"key" octet-string ,pass)
                     (#"salt" octet-string ,salt #:?)
                     (#"info" octet-string ,info #:?)))]
          [(list 'concat _)
           ;; SSKDF; params0 contains "digest"
           (define-values (info key-size)
             (check/ref-config '(info key-size) config config:info-kdf "SSKDF"))
           (values key-size
                   `((#"key" octet-string ,pass)
                     (#"salt" octet-string ,salt)
                     (#"info" octet-string ,info #:?)))]
          [(list 'concat 'hmac _)
           ;; SSKDF; params0 contains "digest", "mac"
           (define-values (info key-size)
             (check/ref-config '(info key-size) config config:info-kdf "SSKDF-HMAC"))
           (values key-size
                   `((#"key" octet-string ,pass)
                     (#"salt" octet-string ,salt)
                     (#"info" octet-string ,info #:?)))]
          [(list 'ans-x9.63 _)
           ;; X963KDF; params0 contains "digest"
           (define-values (info key-size)
             (check/ref-config '(info key-size) config config:info-kdf "X963KDF"))
           (values key-size
                   `((#"key" octet-string ,pass)
                     (#"info" octet-string ,info #:?)))]
          ))
      (define ctx (HANDLEp (EVP_KDF_CTX_new evp)))
      (define key (make-bytes key-size))
      (define params (make-param-array (append params0 params1)))
      (HANDLEp (EVP_KDF_derive ctx key key-size params))
      key)

    (define/override (pwhash config pass)
      (match spec
        ['scrypt
         (kdf-pwhash-scrypt this config pass)]
        [(list 'pbkdf2 'hmac _)
         (kdf-pwhash-pbkdf2 this spec config pass)]
        [(or 'argon2d 'argon2i 'argon2id)
         (kdf-pwhash-argon2 this config pass)]
        [_ (super pwhash config pass)]))

    (define/override (pwhash-verify pass cred)
      (kdf-pwhash-verify this pass cred))

    (define/override (salt-allowed?) salt?)
    (define/override (check-salt salt)
      (when (and salt? (not salt))
        (crypto-error "salt required for KDF\n  KDF: ~a" (about)))
      (when (and (not salt?) salt)
        (crypto-error "salt not allowed for KDF\n  KDF: ~a" (about)))
      salt)
    ))
