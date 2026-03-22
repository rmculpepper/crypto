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
    (init-field evp params0)
    (inherit-field spec)
    (super-new)

    (define/override (-derive key-size config pass salt)
      (define params1
        (match spec
          [(or 'argon2d 'argon2i 'argon2id)
           ;; params0 is empty
           (define-values (t m p v)
             (check/ref-config '(t m p v) config config:argon2-kdf "Argon2"))
           `((#"pass" octet-string ,pass)
             (#"salt" octet-string ,salt)
             (#"iter" uint ,t)
             (#"memcost" uint ,m)
             (#"lanes" uint ,p)
             (#"version" uint ,v))]
          [(list 'pbkdf2 'hmac _)
           ;; params0 contains "digest"
           (define iters
             (check/ref-config '(iterations) config config:pbkdf2-kdf "PBKDF2"))
           `((#"pass" octet-string ,pass)
             (#"salt" octet-string ,salt)
             (#"iter" uint ,iters))]
          ['scrypt
           ;; params0 is empty
           (define-values (N ln p r)
             (check/ref-config '(N ln p r) config config:scrypt-kdf "scrypt"))
           `((#"pass" octet-string ,pass)
             (#"salt" octet-string ,salt)
             (#"n" ulong ,(or N (expt 2 ln)))
             (#"r" uint ,r)
             (#"p" uint ,p))]
          [(list 'hkdf _)
           ;; params0 contains "digest"
           (define info (check/ref-config '(info) config config:info-kdf "HKDF"))
           `((#"key" octet-string ,pass)
             (#"salt" octet-string ,salt #:?)
             (#"info" octet-string ,info #:?))]
          [(list 'concat _)
           ;; SSKDF; params0 contains "digest"
           (define info (check/ref-config '(info) config config:info-kdf "SSKDF"))
           `((#"key" octet-string ,pass)
             (#"salt" octet-string ,salt)
             (#"info" octet-string ,info #:?))]
          [(list 'concat 'hmac _)
           ;; SSKDF; params0 contains "digest", "mac"
           (define info (check/ref-config '(info) config config:info-kdf "SSKDF-HMAC"))
           `((#"key" octet-string ,pass)
             (#"salt" octet-string ,salt)
             (#"info" octet-string ,info #:?))]
          [(list 'ans-x9.63 _)
           ;; X963KDF; params0 contains "digest"
           (define info (check/ref-config '(info) config config:info-kdf "X963KDF"))
           `((#"key" octet-string ,pass)
             (#"info" octet-string ,info #:?))]
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
    ))
