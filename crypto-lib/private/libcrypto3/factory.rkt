;; Copyright 2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/class
         racket/match
         ffi/unsafe
         "../common/interfaces.rkt"
         "../common/catalog.rkt"
         "../common/common.rkt"
         "../common/factory.rkt"
         "ffi.rkt"
         "digest.rkt"
         #;"cipher.rkt"
         #;"pkey.rkt"
         #;"kdf.rkt")
(provide libcrypto-factory)

(define digest-mapping
  #hasheq(;; DigestSpec => String
          [sha512/224 . "sha512-224"]
          [sha512/256 . "sha512-256"]
          ))

;; ----------------------------------------

(define libcrypto3-factory%
  (class* factory-base% (factory<%>)
    (inherit get-digest get-cipher get-pk get-kdf)
    (super-new [ok? libcrypto3-ok?]
               [load-error #f])

    (field [libctx (and libcrypto3-ok? (OSSL_LIB_CTX_new))])
    (when libctx
      (OSSL_PROVIDER_load libctx "default")
      (OSSL_PROVIDER_load libctx "legacy"))

    (define/public (get-libctx) libctx)

    (define/override (get-name) 'libcrypto)
    (define/override (get-version)
      (and libcrypto3-ok?
           (list (OPENSSL_version_major)
                 (OPENSSL_version_minor)
                 (OPENSSL_version_patch))))

    (define/override (-get-digest info)
      (define spec (send info get-spec))
      (define name (or (hash-ref digest-mapping spec #f)
                       (symbol->string spec)))
      (cond [(EVP_MD_fetch libctx name #f)
             => (lambda (md)
                  (new libcrypto3-digest-impl%
                       (info info)
                       (factory this)
                       (md md)))]
            [else #f]))

    ))

(define libcrypto-factory (new libcrypto3-factory%))
