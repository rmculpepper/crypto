;; Copyright 2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require (for-syntax racket/base)
         racket/match
         ffi/unsafe
         ffi/unsafe/alloc
         ffi/unsafe/define
         ffi/unsafe/atomic
         racket/runtime-path
         (only-in openssl/libcrypto
                  libcrypto
                  libcrypto-load-fail-reason)
         "../common/ffi.rkt"
         "../common/error.rkt")
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

(define ERR_TXT_STRING-bit 1)

(define-crypto ERR_get_error_all
  (_fun [file : #|const char **|# _pointer = #f]
        [line : #|int *|# _pointer = #f]
        [func : #|const char **|# _pointer = #f]
        [data : #|const char **|# (_ptr o _pointer)]
        [flags : (_ptr o _int)]
        -> [errcode : _ulong]
        -> (cond [(zero? errcode) (values 0 #f)]
                 [(bitwise-bit-set? flags ERR_TXT_STRING-bit)
                  (values errcode (cast data _pointer _string))]
                 [else (values errcode #f)])))

(define-crypto ERR_lib_error_string
  (_fun [errcode : _ulong] -> _string))
(define-crypto ERR_reason_error_string
  (_fun [errcode : _ulong] -> _string))

(define-syntax NOERR
  ;; Unconditionally ignore and discard any errors.
  (syntax-rules ()
    [(NOERR expr)
     (let ()
       (start-uninterruptible)
       (begin0 expr
         (clear-error-queue)
         (end-uninterruptible)))]))

(define-syntax HANDLE
  ;; Unconditionally check error state.
  (syntax-rules ()
    [(HANDLE expr)
     (HANDLE expr (try-car 'expr))]
    [(HANDLE expr op)
     (let ()
       (start-uninterruptible)
       (begin0 expr
         (cond [(zero? (ERR_peek_error))
                (end-uninterruptible)]
               [else
                (end-uninterruptible/handle-error op)])))]))

(define-syntax HANDLEp
  ;; Only check for error if pointer result is #f (NULL).
  ;; (Also used for other X-or-false return values, where #f means error.)
  (syntax-rules ()
    [(HANDLEp expr)
     (HANDLEp expr (try-car 'expr))]
    [(HANDLEp expr op)
     (let ()
       (start-uninterruptible)
       (let ([r expr])
         (cond [r (begin (end-uninterruptible) r)]
               [else (begin (end-uninterruptible/handle-error op) #f)])))]))

(define (ok-result? n) (> n 0))

(define (try-car v) (if (pair? v) (car v) #f))

(define (end-uninterruptible/handle-error op)
  (define-values (errcode message) (ERR_get_error_all))
  (clear-error-queue)
  (end-uninterruptible)
  (unless (zero? errcode) (raise-error op errcode message)))

(define (raise-error op errcode message)
  (define lib (ERR_lib_error_string errcode))
  (define reason (ERR_reason_error_string errcode))
  (define message-line (if message (format ";\n ~a" message) ""))
  (define op-line (if op (format "\n  operation: ~a" op) ""))
  (crypto-error "~a: ~a~a~a" lib reason message-line op-line))

(define (clear-error-queue)
  (unless (zero? (ERR_get_error)) (clear-error-queue)))

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
        -> [r : _int] -> (ok-result? r)))

;; ----------------------------------------
;; Parameters

(define-cstruct _ossl_param_st
  ([key _pointer]
   [type _uint]
   [data _pointer]
   [data_size _size]
   [return_size _size]))

(define _OSSL_PARAM _ossl_param_st-pointer)
(define _OSSL_PARAM-array _ossl_param_st-pointer/null)

(define OSSL_PARAM_INTEGER              1)
(define OSSL_PARAM_UNSIGNED_INTEGER     2)
(define OSSL_PARAM_REAL                 3)
(define OSSL_PARAM_UTF8_STRING          4)
(define OSSL_PARAM_OCTET_STRING         5)

(define (make-param-array ps0)
  ;; Allocates a single block holding OSSL_PARAM[] followed by data.
  (define (ceiling-align n)
    (let ([n+7 (+ n 7)])
      (- n+7 (modulo n+7 8))))
  (define (key-size key)
    (ceiling-align (add1 (bytes-length key))))
  (define (data-size type data)
    (match type
      [(or 'int 'uint) (compiler-sizeof 'int)]
      [(or 'long 'ulong) (compiler-sizeof 'long)]
      ['octet-string (ceiling-align (bytes-length data))]
      ['utf8-string (ceiling-align (add1 (string-utf-8-length data)))]))
  (define (row-size row)
    (match row
      [(list* key type data _)
       (+ (key-size key)
          (data-size type data))]))
  ;; ----
  (define (keep-row? p) (match p [(list _ _ #f #:?) #f] [_ #t]))
  (define ps (filter keep-row? ps0))
  (define params-len (* (add1 (length ps)) (ctype-sizeof _ossl_param_st)))
  (define data-len (for/sum ([p (in-list ps)]) (row-size p)))
  (define buf (malloc (+ params-len data-len) 'atomic-interior))
  (cpointer-push-tag! buf ossl_param_st-tag)
  (memset buf 0 (+ params-len data-len)) ;; handles string NULs, END param
  (define dpointer (ptr-add buf params-len))
  (for ([p (in-list ps)] [pindex (in-naturals)])
    (match-define (list* key type data _) p)
    (define param (ptr-add buf pindex _ossl_param_st))
    ;; Assert (ossl_param_st? param); ptr-add preserves tags.
    (memcpy dpointer key (bytes-length key))
    (set-ossl_param_st-key! param dpointer)
    (ptr-add! dpointer (key-size key))
    (set-ossl_param_st-data! param dpointer)
    (match type
      ['int
       (set-ossl_param_st-type! param OSSL_PARAM_INTEGER)
       (set-ossl_param_st-data_size! param (ctype-sizeof _int))
       (ptr-set! dpointer _int data)]
      ['uint
       (set-ossl_param_st-type! param OSSL_PARAM_UNSIGNED_INTEGER)
       (set-ossl_param_st-data_size! param (ctype-sizeof _uint))
       (ptr-set! dpointer _uint data)]
      ['long
       (set-ossl_param_st-type! param OSSL_PARAM_INTEGER)
       (set-ossl_param_st-data_size! param (ctype-sizeof _long))
       (ptr-set! dpointer _long data)]
      ['ulong
       (set-ossl_param_st-type! param OSSL_PARAM_UNSIGNED_INTEGER)
       (set-ossl_param_st-data_size! param (ctype-sizeof _long))
       (ptr-set! dpointer _ulong data)]
      ['octet-string
       (set-ossl_param_st-type! param OSSL_PARAM_OCTET_STRING)
       (set-ossl_param_st-data_size! param (bytes-length data))
       (memcpy dpointer data (bytes-length data))]
      ['utf8-string
       (set-ossl_param_st-type! param OSSL_PARAM_UTF8_STRING)
       (define data-bs (string->bytes/utf-8 data))
       (set-ossl_param_st-data_size! param (bytes-length data-bs))
       (memcpy dpointer data-bs (bytes-length data-bs))])
    (ptr-add! dpointer (data-size type data)))
  buf)

;; ============================================================
;; Algorithms

;; ----------------------------------------
;; Digest

(define-cpointer-type _EVP_MD)
(define-cpointer-type _EVP_MD_CTX)

(define-crypto EVP_MD_free
  (_fun [md : _EVP_MD] -> _void)
  #:wrap (deallocator))

(define-crypto EVP_MD_fetch
  (_fun [ctx : _OSSL_LIB_CTX/null]
        [algorithm : #;const _string]
        [properties : #;const _string]
        -> _EVP_MD/null)
  #:wrap (allocator EVP_MD_free))

;; EVP_Q_Digest just calls fetch then EVP_Digest
(define-crypto EVP_Digest
  (_fun [data : #;const _pointer]
        [datalen : _size]
        [out : _pointer]
        [outlen : (_ptr o _size)]
        [md : #;const _EVP_MD]
        [engine : _pointer = #f]
        -> [r : _int] -> (and (ok-result? r) outlen)))

;; MD_CTX states: uninit | after-update | after-final

(define-crypto EVP_MD_CTX_free
  (_fun [ctx : _EVP_MD_CTX] -> _void)
  #:wrap (deallocator))
(define-crypto EVP_MD_CTX_new
  (_fun -> _EVP_MD_CTX) ;; POST: uninit
  #:wrap (allocator EVP_MD_CTX_free))

(define EVP_MD_CTX_dup  ;; added in v3.1
  (cond [(get-ffi-obj 'EVP_MD_CTX_dup libcrypto _fpointer (lambda () #f))
         (define-crypto EVP_MD_CTX_dup
           (_fun [ctx : #;const _EVP_MD_CTX]
                 -> _EVP_MD_CTX/null)
           #:wrap (allocator EVP_MD_CTX_free))
         EVP_MD_CTX_dup]
        [else
         (define-crypto EVP_MD_CTX_copy
           (_fun [out : _EVP_MD_CTX]
                 [in : #;const _EVP_MD_CTX]
                 -> [r : _int] -> (ok-result? r)))
         (define (EVP_MD_CTX_dup ctx)
           (define ctx2 (EVP_MD_CTX_new))
           (and ctx2 (EVP_MD_CTX_copy ctx2 ctx) ctx2))
         EVP_MD_CTX_dup]))

(define-crypto EVP_DigestInit_ex2
  (_fun [ctx : _EVP_MD_CTX] ;; if uninit, type must not be NULL; POST: after-update
        [type : #;const _EVP_MD/null]
        [params : _OSSL_PARAM-array]
        -> [r : _int] -> (ok-result? r)))

(define-crypto EVP_DigestUpdate
  (_fun [ctx : _EVP_MD_CTX] ;; PRE: after-update; POST: after-update
        [data : #;const _pointer]
        [count : _size]
        -> [r : _int] -> (ok-result? r)))

(define-crypto EVP_DigestFinal_ex
  (_fun [ctx : _EVP_MD_CTX] ;; PRE: after-update; POST: after-final
        [md : _pointer]
        [mdlen : (_ptr o _uint)]
        -> [r : _int] -> (and (ok-result? r) mdlen)))

(define-crypto EVP_DigestFinalXOF
  (_fun [ctx : _EVP_MD_CTX] ;; PRE: after-update; POST: after-final
        [md : _pointer]
        [len : _size]
        -> [r : _int] -> (ok-result? r)))

(define-crypto EVP_MD_get0_name
  (_fun [md : #;const _EVP_MD] -> _string))
(define-crypto EVP_MD_get0_description
  (_fun [md : #;const _EVP_MD] -> _string))

(define-crypto EVP_MD_get_size
  (_fun [md : #;const _EVP_MD] -> _int))
(define-crypto EVP_MD_get_block_size
  (_fun [md : #;const _EVP_MD] -> _int))

(define-crypto EVP_MD_do_all_provided
  (_fun [libctx : _OSSL_LIB_CTX]
        [fn : (_fun [md : _EVP_MD] [arg : _pointer] -> _void)]
        [arg : _pointer]
        -> _void))

;; ----------------------------------------
;; MAC

(define-cpointer-type _EVP_MAC)
(define-cpointer-type _EVP_MAC_CTX)

(define-crypto EVP_MAC_free
  (_fun [mac : _EVP_MAC] -> _void)
  #:wrap (deallocator))

(define-crypto EVP_MAC_fetch
  (_fun [libctx : _OSSL_LIB_CTX/null]
        [algorithm : #;const _string]
        [properties : #;const _string]
        -> _EVP_MAC/null)
  #:wrap (allocator EVP_MAC_free))

(define-crypto EVP_MAC_get0_name
  (_fun [mac : _EVP_MAC] -> _string))
(define-crypto EVP_MAC_get0_description
  (_fun [mac : #;const _EVP_MAC] -> _string))

(define-crypto EVP_Q_mac
  (_fun [libctx : _OSSL_LIB_CTX]
        [name : #;const _string]
        [propq : #;const _string]
        [subalg : #;const _string] ;; "digest" or "cipher" param
        [params : #;const _OSSL_PARAM-array]
        [key : #;const _pointer]
        [keylen : _size]
        [data : #;const _pointer]
        [datalen : _size]
        [out : _pointer]
        [outsize : _size]
        [outlen : (_ptr o _size)]
        -> [r : _pointer] -> (and r outlen)))

(define-crypto EVP_MAC_CTX_free
  (_fun [ctx : _EVP_MAC_CTX] -> _void)
  #:wrap (deallocator))
(define-crypto EVP_MAC_CTX_new
  (_fun [mac : _EVP_MAC] -> _EVP_MAC_CTX/null)
  #:wrap (allocator EVP_MAC_CTX_free))

(define-crypto EVP_MAC_CTX_dup
  (_fun [src : #;const _EVP_MAC_CTX]
        -> _EVP_MAC_CTX/null))

(define-crypto EVP_MAC_CTX_get_mac_size
  (_fun [ctx : _EVP_MAC_CTX] -> _size))
(define-crypto EVP_MAC_CTX_get_block_size
  (_fun [ctx : _EVP_MAC_CTX] -> _size))

(define-crypto EVP_MAC_init
  (_fun [ctx : _EVP_MAC_CTX]
        [key : _bytes]
        [keylen : _size = (bytes-length key)]
        [params : #;const _OSSL_PARAM-array]
        -> [r : _int] -> (ok-result? r)))
(define-crypto EVP_MAC_update
  (_fun [ctx : _EVP_MAC_CTX]
        [data : _pointer]
        [datalen : _size]
        -> [r : _int] -> (ok-result? r)))
(define-crypto EVP_MAC_final
  (_fun [ctx : _EVP_MAC_CTX]
        [out : _pointer]
        [outlen : (_ptr o _size)]
        [outsize : _size]
        -> [r : _int] -> (and (ok-result? r) outlen)))
(define-crypto EVP_MAC_finalXOF
  (_fun [ctx : _EVP_MAC_CTX]
        [out : _pointer]
        [outsize : _size]
        -> [r : _int] -> (ok-result? r)))

(define-crypto EVP_MAC_do_all_provided
  (_fun [libctx : _OSSL_LIB_CTX]
        [fn : (_fun [mac : _EVP_MAC] [arg : _pointer] -> _void)]
        [arg : _pointer]
        -> _void))

;; ----------------------------------------
;; Cipher

(define-cpointer-type _EVP_CIPHER)
(define-cpointer-type _EVP_CIPHER_CTX)

(define-crypto EVP_CIPHER_free
  (_fun [cipher : _EVP_CIPHER] -> _void)
  #:wrap (deallocator))

(define-crypto EVP_CIPHER_fetch
  (_fun [ctx : _OSSL_LIB_CTX/null]
        [algorithm : #;const _string]
        [properties : #;const _string]
        -> _EVP_CIPHER/null)
  #:wrap (allocator EVP_CIPHER_free))

(define-crypto EVP_CIPHER_CTX_free
  (_fun [ctx : _EVP_CIPHER_CTX] -> _void)
  #:wrap (deallocator))

(define-crypto EVP_CIPHER_CTX_new
  (_fun -> _EVP_CIPHER_CTX/null)
  #:wrap (allocator EVP_CIPHER_CTX_free))

(define-crypto EVP_CIPHER_CTX_reset
  (_fun _EVP_CIPHER_CTX -> [r : _int] -> (ok-result? r)))

(define-crypto EVP_CipherInit_ex2
  (_fun [ctx : _EVP_CIPHER_CTX]
        [type : #;const _EVP_CIPHER/null]
        [key : #;const _pointer]
        [iv : #;const _pointer]
        [enc : _int]
        [params : #;const _OSSL_PARAM-array]
        -> [r : _int] -> (ok-result? r)))

(define-crypto EVP_CipherUpdate
  (_fun [ctx : _EVP_CIPHER_CTX]
        [out : _pointer]
        [outlen : (_ptr o _int)]
        [in : #;const _pointer]
        [inlen : _int]
        -> [r : _int] -> (and (ok-result? r) outlen)))

(define-crypto EVP_CipherFinal_ex
  (_fun [ctx : _EVP_CIPHER_CTX]
        [out : _pointer]
        [outlen : (_ptr o _int)]
        -> [r : _int] -> (and (ok-result? r) outlen)))

(define-crypto EVP_CIPHER_CTX_set_padding
  (_fun [ctx : _EVP_CIPHER_CTX]
        [padding : _int]
        -> [r : _int] -> (ok-result? r)))
(define-crypto EVP_CIPHER_CTX_set_key_length
  (_fun [ctx : _EVP_CIPHER_CTX]
        [keylen : _int]
        -> [r : _int] -> (ok-result? r)))

(define-crypto EVP_CIPHER_CTX_set_params
  (_fun [ctx : _EVP_CIPHER_CTX]
        [params : #;const _OSSL_PARAM-array]
        -> [r : _int] -> (ok-result? r)))

(define-crypto EVP_CIPHER_CTX_ctrl
  (_fun [ctx : _EVP_CIPHER_CTX]
        [cmd : _int]
        [p1 : _int]
        [p2 : _pointer]
        -> [r : _int] -> (ok-result? r)))

(define EVP_CTRL_AEAD_SET_IVLEN     #x9)
(define EVP_CTRL_AEAD_GET_TAG       #x10)
(define EVP_CTRL_AEAD_SET_TAG       #x11)

(define-crypto EVP_CIPHER_get0_name
  (_fun [cipher : #;const _EVP_CIPHER] -> _string))
(define-crypto EVP_CIPHER_get_block_size
  (_fun [cipher : #;const _EVP_CIPHER] -> _int))
(define-crypto EVP_CIPHER_get_key_length
  (_fun [cipher : #;const _EVP_CIPHER] -> _int))
(define-crypto EVP_CIPHER_get_iv_length
  (_fun [cipher : #;const _EVP_CIPHER] -> _int))

(define-crypto EVP_CIPHER_do_all_provided
  (_fun [libctx : _OSSL_LIB_CTX]
        [fn : (_fun [cipher : _EVP_CIPHER] [arg : _pointer] -> _void)]
        [arg : _pointer]
        -> _void))
