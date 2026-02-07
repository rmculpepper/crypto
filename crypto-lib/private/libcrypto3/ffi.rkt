;; Copyright 2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require (for-syntax racket/base)
         ffi/unsafe
         ffi/unsafe/alloc
         ffi/unsafe/define
         racket/runtime-path
         (only-in openssl/libcrypto
                  libcrypto
                  libcrypto-load-fail-reason)
         "../common/ffi.rkt")
(provide (protect-out (all-defined-out)))

(define-ffi-definer define-crypto libcrypto
  #:default-make-fail make-not-available)

;; ----------------------------------------
;; Version

(define-crypto OpenSSL_version_num (_fun -> _ulong)
  #:fail (lambda () (lambda () 0)))
(define-crypto OPENSSL_version_major (_fun -> _uint)
  #:fail (lambda () (lambda () 0)))
(define-crypto OPENSSL_version_minor (_fun -> _uint))
(define-crypto OPENSSL_version_patch (_fun -> _uint))
(define-crypto OPENSSL_version_pre_release (_fun -> _string))
(define-crypto OPENSSL_version_build_metadata (_fun -> _string))

;; (define-crypto OpenSSL_version (_fun [t : _int] -> _string))
;; (define OPENSSL_VERSION                0)
;; (define OPENSSL_CFLAGS                 1)
;; (define OPENSSL_BUILT_ON               2)
;; (define OPENSSL_PLATFORM               3)
;; (define OPENSSL_DIR                    4)
;; (define OPENSSL_ENGINES_DIR            5)
;; (define OPENSSL_VERSION_STRING         6)
;; (define OPENSSL_FULL_VERSION_STRING    7)
;; (define OPENSSL_MODULES_DIR            8)
;; (define OPENSSL_CPU_INFO               9)

(define-crypto OPENSSL_info (_fun [t : _int] -> _string))
(define OPENSSL_INFO_CONFIG_DIR                1001)
(define OPENSSL_INFO_ENGINES_DIR               1002)
(define OPENSSL_INFO_MODULES_DIR               1003)
(define OPENSSL_INFO_DSO_EXTENSION             1004)
(define OPENSSL_INFO_DIR_FILENAME_SEPARATOR    1005)
(define OPENSSL_INFO_LIST_SEPARATOR            1006)
(define OPENSSL_INFO_SEED_SOURCE               1007)
(define OPENSSL_INFO_CPU_SETTINGS              1008)

(define libcrypto3-ok? (and libcrypto (= (OPENSSL_version_major) 3)))

(define (get-ok? fun-name)
  (and libcrypto3-ok? (get-ffi-obj fun-name libcrypto _fpointer (lambda () #f)) #t))

;; ----------------------------------------
;; Error handling

(define-crypto ERR_peek_error (_fun -> _ulong)) ;; 0 = no error
(define-crypto ERR_get_error  (_fun -> _ulong))

(define-crypto ERR_lib_error_string
  (_fun [errcode : _ulong] -> _string))
(define-crypto ERR_reason_error_string
  (_fun [errcode : _ulong] -> _string))

;; (define-crypto ERR_get_error_all
;;   (_fun [file : (_ptr o _string/null)]
;;         [line : (_ptr o _int)]
;;         [func : (_ptr o _string/null)]
;;         [data : (_ptr o _pointer) _pointer]
;;         [flags : (_ptr o _int)]
;;         -> [errcode : _ulong]
;;         -> (values errcode file line func data flags)))

;; (define-crypto ERR_peek_error_all
;;   (_fun [file : (_ptr o _string/null)]
;;         [line : (_ptr o _int)]
;;         [func : (_ptr o _string/null)]
;;         [data : (_ptr o _pointer) _pointer]
;;         [flags : (_ptr o _int)]
;;         -> [errcode : _ulong]
;;         -> (values errcode file line func data flags)))

;; ----------------------------------------
;; Library Contexts

(define-cpointer-type _OSSL_LIB_CTX)

(define-crypto OSSL_LIB_CTX_free
  (_fun [ctx : _OSSL_LIB_CTX] -> _void)
  #:wrap (deallocator))
(define-crypto OSSL_LIB_CTX_new (_fun -> _OSSL_LIB_CTX/null)
  #:wrap (allocator OSSL_LIB_CTX_free))

;; ----------------------------------------
;; Providers

(define-cpointer-type _OSSL_PROVIDER)

(define-crypto OSSL_PROVIDER_load
  (_fun [libctx : _OSSL_LIB_CTX] [name : _string] -> _OSSL_PROVIDER/null))
(define-crypto OSSL_PROVIDER_try_load
  (_fun [libctx : _OSSL_LIB_CTX] [name : _string] [retain_fallbacks : _int]
        -> _OSSL_PROVIDER/null))
(define-crypto OSSL_PROVIDER_unload
  (_fun [prov : _OSSL_PROVIDER] -> _int))
(define-crypto OSSL_PROVIDER_available
  (_fun [libctx : _OSSL_LIB_CTX] [_name : _string] -> _bool))
(define-crypto OSSL_PROVIDER_do_all
  (_fun [libctx : _OSSL_LIB_CTX]
        [cb : (_fun [provider : _OSSL_PROVIDER] [cbdata : _pointer] -> _int)]
        [cbdata : _pointer]
        -> _int))
