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

    (define/override (-get-kdf spec)
      (define (fetch kdf-name)
        (NOERR (EVP_KDF_fetch libctx kdf-name #f)))
      (define (make-impl evp params0)
        (new libcrypto3-kdf-impl% (factory this) (spec spec) (evp evp)
             (params0 params0)))
      (define (check/get-digest-name dspec)
        (define di (get-normal-digest dspec)) ;; check availability
        (and di (get-digest-lcname dspec)))
      (or (match spec
            [(or 'argon2d 'argon2i 'argon2id) ;; added in v3.2
             (define evp (fetch (symbol->string spec)))
             (and evp (make-impl evp null))]
            ['scrypt
             (define evp (fetch "scrypt"))
             (and evp (make-impl evp null))]
            [(list 'pbkdf2 'hmac di)
             (define evp (fetch "pbkdf2"))
             (define dname (check/get-digest-name di))
             (and evp dname (make-impl evp `((#"digest" utf8-string ,dname))))]
            [(list 'hkdf di)
             (define evp (fetch "hkdf"))
             (define dname (check/get-digest-name di))
             (and evp dname (make-impl evp `((#"digest" utf8-string ,dname))))]
            [(list 'concat di)
             (define evp (fetch "ssdf"))
             (define dname (check/get-digest-name di))
             (and evp dname (make-impl evp `((#"digest" utf8-string ,dname))))]
            [(list 'concat 'hmac di)
             (define evp (fetch "ssdf"))
             (define dname (check/get-digest-name di))
             (and evp dname (make-impl evp `((#"digest" utf8-string ,dname)
                                             (#"mac" utf8-string "hmac"))))]
            [(list 'ans-x9.63 di)
             (define evp (fetch "X963KDF"))
             (define dname (check/get-digest-name di))
             (and evp dname (make-impl evp `((#"digest" utf8-string ,dname))))]
            [_ #f])
          (super -get-kdf spec)))





(define libcrypto3-kdf-impl%
  (class kdf-impl-base%
    (inherit about get-spec)
    (init-field evp params0)
    (super-new)

    (define/override (-derive key-size config pass salt)
      (define params1
        (match (get-spec)
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
    ))
