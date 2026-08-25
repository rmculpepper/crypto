;; Copyright 2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         ffi/unsafe
         "../common/interfaces.rkt"
         "../common/catalog.rkt"
         "../common/common.rkt"
         "../common/factory.rkt"
         "ffi.rkt"
         "digest.rkt"
         "cipher.rkt"
         #;"pkey.rkt"
         "kdf.rkt")
(provide libcrypto-factory)

(define (libcrypto3-info key)
  (case key
    ;; OpenSSL_info keys
    [(OPENSSL_INFO_CONFIG_DIR)
     (OPENSSL_info OPENSSL_INFO_CONFIG_DIR)]
    [(OPENSSL_INFO_ENGINES_DIR)
     (OPENSSL_info OPENSSL_INFO_ENGINES_DIR)]
    [(OPENSSL_INFO_MODULES_DIR)
     (OPENSSL_info OPENSSL_INFO_MODULES_DIR)]
    [(OPENSSL_INFO_DSO_EXTENSION)
     (OPENSSL_info OPENSSL_INFO_DSO_EXTENSION)]
    [(OPENSSL_INFO_DIR_FILENAME_SEPARATOR)
     (OPENSSL_info OPENSSL_INFO_DIR_FILENAME_SEPARATOR)]
    [(OPENSSL_INFO_LIST_SEPARATOR)
     (OPENSSL_info OPENSSL_INFO_LIST_SEPARATOR)]
    [(OPENSSL_INFO_SEED_SOURCE)
     (OPENSSL_info OPENSSL_INFO_SEED_SOURCE)]
    [(OPENSSL_INFO_CPU_SETTINGS)
     (OPENSSL_info OPENSSL_INFO_CPU_SETTINGS)]
    ;; OpenSSL_version keys
    [(OPENSSL_VERSION)
     (OpenSSL_version OPENSSL_VERSION)]
    [(OPENSSL_CFLAGS)
     (OpenSSL_version OPENSSL_CFLAGS)]
    [(OPENSSL_BUILT_ON)
     (OpenSSL_version OPENSSL_BUILT_ON)]
    [(OPENSSL_PLATFORM)
     (OpenSSL_version OPENSSL_PLATFORM)]
    [(OPENSSL_DIR)
     (OpenSSL_version OPENSSL_DIR)]
    [(OPENSSL_ENGINES_DIR)
     (OpenSSL_version OPENSSL_ENGINES_DIR)]
    [(OPENSSL_VERSION_STRING)
     (OpenSSL_version OPENSSL_VERSION_STRING)]
    [(OPENSSL_FULL_VERSION_STRING)
     (OpenSSL_version OPENSSL_FULL_VERSION_STRING)]
    [(OPENSSL_MODULES_DIR)
     (OpenSSL_version OPENSSL_MODULES_DIR)]
    [(OPENSSL_CPU_INFO)
     (OpenSSL_version OPENSSL_CPU_INFO)]
    ;; OpenSSL all
    [(openssl-info)
     (map (lambda (sym) (list sym (libcrypto3-info sym)))
          '(OPENSSL_VERSION
            OPENSSL_CFLAGS
            OPENSSL_BUILT_ON
            OPENSSL_PLATFORM
            ;OPENSSL_DIR
            ;OPENSSL_ENGINES_DIR
            OPENSSL_VERSION_STRING
            OPENSSL_FULL_VERSION_STRING
            ;OPENSSL_MODULES_DIR
            OPENSSL_CPU_INFO
            OPENSSL_INFO_CONFIG_DIR
            OPENSSL_INFO_ENGINES_DIR
            OPENSSL_INFO_MODULES_DIR
            OPENSSL_INFO_DSO_EXTENSION
            OPENSSL_INFO_DIR_FILENAME_SEPARATOR
            OPENSSL_INFO_LIST_SEPARATOR
            OPENSSL_INFO_SEED_SOURCE
            OPENSSL_INFO_CPU_SETTINGS))]
    ;; Standard info

    #;
    [(all-ec-curves)
     (sort (get-all-curve-names) string-ci<?
           #:key symbol->string #:cache-keys? #t)]

    [(all-eddsa-curves)
     '(ed25519 ed448)]
    [(all-ecx-curves)
     '(x25519 x448)]
    [else #f]))

;; ----------------------------------------

(define (make-libcrypto-factory)
  (define libctx (and libcrypto3-ok? (HANDLEp (OSSL_LIB_CTX_new))))
  (when libctx
    (HANDLEp (OSSL_PROVIDER_load libctx "default"))
    (NOERR (OSSL_PROVIDER_load libctx "legacy")))
  (make-factory
   #:name 'libcrypto
   #:version libcrypto3-version
   #:ok? libcrypto3-ok?
   #:load-error #f ;; FIXME
   #:inner-ctx libctx

   #:get-info libcrypto3-info
   #:get-digest libcrypto3-fetch-digest
   #:get-cipher libcrypto3-fetch-cipher
   #:get-kdf libcrypto3-fetch-kdf
   ))

(define libcrypto-factory
  (make-libcrypto-factory))

#;
(define/override (print-lib-info)
  (super print-lib-info)
  (when (and libcrypto (> (OpenSSL_version_num) 0))
    (printf " OpenSSL_version_num: #x~x\n" (OpenSSL_version_num)))
  (when libcrypto3-ok?
    (printf " OPENSSL_VERSION_TEXT: ~s\n" (OpenSSL_version OPENSSL_VERSION)))
  (when (and libcrypto (not libcrypto3-ok?))
    (printf " status: library version not supported!\n")))
