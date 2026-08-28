;; Copyright 2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/kdf.rkt"
         "../common/error.rkt"
         "ffi.rkt"
         "digest.rkt")
(provide libcrypto3-fetch-kdf)

(define (libcrypto3-fetch-kdf factory info)
  (define libctx ($factory-inner-ctx factory))
  (define spec ($get-spec info))
  (define (fetch kdf-name)
    (NOERR (EVP_KDF_fetch libctx kdf-name #f)))
  (define (check/get-digest-name dspec)
    (and ($fetch-digest factory dspec) ;; check availability
         (get-digest-lcname dspec)))
  (define inner
    (match spec
      [(or 'argon2d 'argon2i 'argon2id) ;; added in v3.2
       (define evp (fetch (symbol->string spec)))
       (and evp (argon2-inner-impl evp))]
      ['scrypt
       (define evp (fetch "scrypt"))
       (and evp (scrypt-inner-impl evp))]
      [(list 'pbkdf2 'hmac dspec)
       (define evp (fetch "PBKDF2"))
       (define dname (check/get-digest-name dspec))
       (and evp dname (pbkdf2-inner-impl evp dname))]
      [(list 'hkdf dspec)
       (define evp (fetch "HKDF"))
       (define dname (check/get-digest-name dspec))
       (and evp dname (hkdf-inner-impl evp dname))]
      [(list 'concat dspec)
       (define evp (fetch "SSKDF"))
       (define dname (check/get-digest-name dspec))
       (and evp dname (concat-inner-impl evp dname))]
      [(list 'concat 'hmac dspec)
       (define evp (fetch "SSKDF"))
       (define dname (check/get-digest-name dspec))
       (and evp dname (concat-hmac-inner-impl evp dname))]
      [(list 'ans-x9.63 dspec)
       (define evp (fetch "X963KDF"))
       (define dname (check/get-digest-name dspec))
       (and evp dname (ans-x9.63-inner-impl evp dname))]
      [_ #f]))
  (make-kdf info factory inner))

;; ------------------------------------------------------------

(define (libcrypto3-do-kdf evp key-size params)
  (define ic (HANDLEp (EVP_KDF_CTX_new evp)))
  (define key (make-bytes key-size))
  (define param-array (make-param-array params))
  (HANDLEp (EVP_KDF_derive ic key key-size param-array))
  key)

(define (argon2-inner-impl evp)
  (make-kdf-inner-impl
   (lambda (kdfi key-size config pass salt)
     (define-values (t m p v)
       (check/ref-config '(t m p v) config config:argon2-kdf #:in kdfi))
     (define params
       `((#"pass" octet-string ,pass)
         (#"salt" octet-string ,salt)
         (#"iter" uint ,t)
         (#"memcost" uint ,m)
         (#"lanes" uint ,p)
         (#"version" uint ,v)))
     (libcrypto3-do-kdf evp key-size params))))

(define (scrypt-inner-impl evp)
  (make-kdf-inner-impl
   (lambda (kdfi key-size config pass salt)
     (define-values (N ln p r)
       (check/ref-config '(N ln p r) config config:scrypt-kdf #:in kdfi))
     (define params
       `((#"pass" octet-string ,pass)
         (#"salt" octet-string ,salt)
         (#"n" ulong ,(or N (expt 2 ln)))
         (#"r" uint ,r)
         (#"p" uint ,p)))
     (libcrypto3-do-kdf evp key-size params))))

(define (pbkdf2-inner-impl evp dname)
  (make-kdf-inner-impl
   (lambda (kdfi key-size config pass salt)
     (define iters
       (check/ref-config '(iterations) config config:pbkdf2-kdf #:in kdfi))
     (define params
       `((#"digest" utf8-string ,dname)
         (#"pass" octet-string ,pass)
         (#"salt" octet-string ,salt)
         (#"iter" uint ,iters)))
     (libcrypto3-do-kdf evp key-size params))))

(define (hkdf-inner-impl evp dname)
  (make-kdf-inner-impl
   (lambda (kdfi key-size config pass salt)
     (define info (check/ref-config '(info) config config:info-kdf #:in kdfi))
     (define params
       `((#"digest" utf8-string ,dname)
         (#"key" octet-string ,pass)
         (#"salt" octet-string ,salt #:?)
         (#"info" octet-string ,info #:?)))
     (libcrypto3-do-kdf evp key-size params))))

(define (concat-inner-impl evp dname)
  (make-kdf-inner-impl
   (lambda (kdfi key-size config pass salt)
     (define info (check/ref-config '(info) config config:info-kdf #:in kdfi))
     (define params
       `((#"digest" utf8-string ,dname)
         (#"key" octet-string ,pass)
         (#"info" octet-string ,info #:?)))
     (libcrypto3-do-kdf evp key-size params))))

(define (concat-hmac-inner-impl evp dname)
  (make-kdf-inner-impl
   (lambda (kdfi key-size config pass salt)
     (define info (check/ref-config '(info) config config:info-kdf #:in kdfi))
     (define params
       `((#"digest" utf8-string ,dname)
         (#"mac" utf8-string "hmac")
         (#"key" octet-string ,pass)
         (#"salt" octet-string ,salt)
         (#"info" octet-string ,info #:?)))
     (libcrypto3-do-kdf evp key-size params))))

(define (ans-x9.63-inner-impl evp dname)
  (make-kdf-inner-impl
   (lambda (kdfi key-size config pass salt)
     (define info (check/ref-config '(info) config config:info-kdf #:in kdfi))
     (define params
       `((#"digest" utf8-string ,dname)
         (#"key" octet-string ,pass)
         (#"info" octet-string ,info #:?)))
     (libcrypto3-do-kdf evp key-size params))))
