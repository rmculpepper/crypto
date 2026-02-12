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
         "../common/base256.rkt"
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
      ['utf8-string (ceiling-align (add1 (string-utf-8-length data)))]
      ['ubignum
       (define bits-length (add1 (integer-length data))) ;; +1 for unsigned
       (define bytes-length (quotient (+ bits-length 7) 8))
       (ceiling-align bytes-length)]))
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
      ['ubignum
       (define bn (unsigned->base256 data (system-big-endian?)))
       (set-ossl_param_st-type! param OSSL_PARAM_UNSIGNED_INTEGER)
       (set-ossl_param_st-data_size! param (bytes-length bn))
       (memcpy dpointer bn (bytes-length bn))]
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

;; ----------------------------------------
;; Nonmoving strings

(define-cpointer-type _nonmoving_string)

;; nonmoving : Bytes -> Pointer
(define (nonmoving bs)
  (define len (bytes-length bs))
  (define p (malloc (add1 len) _byte 'atomic-interior))
  (cpointer-push-tag! p nonmoving_string-tag)
  (memcpy p bs len)
  (ptr-set! p _byte len 0)
  p)

;; ----------------------------------------
;; Bignums

(define-cpointer-type _BIGNUM)

(define-crypto BN_free
  (_fun [bn : _BIGNUM] -> _void))

(define-crypto BN_num_bits
  (_fun [bn : #;const _BIGNUM] -> _int))

(define (BN_num_bytes bn)
  (quotient (+ (BN_num_bits bn) 7) 8))

(define-crypto BN_is_negative
  (_fun [bn : #;const _BIGNUM] -> _bool))

(define-crypto BN_set_negative
  (_fun [bn : _BIGNUM] [neg? : _bool] -> _int))

(define-crypto BN_bn2bin
  (_fun [bn : #;const _BIGNUM]
        [out : _pointer = (make-bytes (BN_num_bytes bn))]
        -> [r : _int] -> (and (ok-result? r) out)))

(define-crypto BN_bin2bn
  (_fun [s : #;const _pointer]
        [len : _int]
        [reuse : _BIGNUM/null = #f]
        -> _BIGNUM/null)
  #:wrap (allocator BN_free))

(define (integer->BIGNUM n)
  (define bn (BN_bin2bn (unsigned->base256 (abs n))))
  (when (and bn (negative? n)) (BN_set_negative bn #t))
  bn)

(define (BIGNUM->integer bn)
  (define n (base256->unsigned (BN_bn2bin bn)))
  (if (BN_is_negative bn) (- n) n))

;; ----------------------------------------
;; EC Curves

(define-cstruct _EC_builtin_curve
  ([nid _int] [comment _pointer]))

(define-crypto EC_get_builtin_curves
  (_fun [out : _pointer] [nitems : _size] -> _size))

(define-crypto OBJ_nid2sn
  (_fun [nid : _int] -> #;const _string))

;; ----------------------------------------
;; Misc

(define-crypto CRYPTO_zalloc
  (_fun [size : _size]
        [file : _pointer = #f]
        [line : _int = 0]
        -> _pointer))

(define-crypto CRYPTO_free
  (_fun [ptr : _pointer]
        [file : _pointer = #f]
        [line : _int = 0]
        -> _void))

(define (pointer->bytes p len)
  (define buf (make-bytes len))
  (memcpy buf p len)
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

;; ----------------------------------------
;; KDF

(define-cpointer-type _EVP_KDF)
(define-cpointer-type _EVP_KDF_CTX)

(define-crypto EVP_KDF_free
  (_fun [kdf : _EVP_KDF] -> _void)
  #:wrap (deallocator))

(define-crypto EVP_KDF_fetch
  (_fun [libctx : _OSSL_LIB_CTX/null]
        [algorithm : #;const _string]
        [properties : #;const _string]
        -> _EVP_KDF/null)
  #:wrap (allocator EVP_KDF_free))

(define-crypto EVP_KDF_get0_name
  (_fun [kdf : #;const _EVP_KDF] -> _string))

(define-crypto EVP_KDF_do_all_provided
  (_fun [libctx : _OSSL_LIB_CTX]
        [fn : (_fun [kdf : _EVP_KDF] [arg : _pointer] -> _void)]
        [arg : _pointer]
        -> _void))

(define-crypto EVP_KDF_names_do_all
  (_fun [libctx : #;const _EVP_KDF]
        [fn : (_fun [name : _string] [data : _pointer] -> _void)]
        [data : _pointer]
        -> _int))

(define-crypto EVP_KDF_CTX_free
  (_fun [kdf : _EVP_KDF_CTX] -> _void)
  #:wrap (deallocator))

(define-crypto EVP_KDF_CTX_new
  (_fun [kdf : _EVP_KDF] -> _EVP_KDF_CTX/null)
  #:wrap (allocator EVP_KDF_CTX_free))

(define-crypto EVP_KDF_derive
  (_fun [ctx : _EVP_KDF_CTX]
        [out : _pointer]
        [outlen : _size]
        [params : _OSSL_PARAM-array]
        -> [r : _int] -> (ok-result? r)))

;; ============================================================
;; PKEY

;; Many int functions have nonzero results other than 1 ("success"),
;; such as -2 for "operation not supported".

(define-cpointer-type _EVP_PKEY)

(define-crypto EVP_PKEY_free
  (_fun [key : _EVP_PKEY] -> _void)
  #:wrap (deallocator))

(define-crypto EVP_PKEY_new
  (_fun -> _EVP_PKEY/null)
  #:wrap (allocator EVP_PKEY_free))

(define-crypto EVP_PKEY_is_a
  (_fun [key : #;const _EVP_PKEY] [type : #;const _string] -> _bool))

(define-crypto EVP_PKEY_get_security_bits
  (_fun [pkey : #;const _EVP_PKEY] -> _int))

(define-crypto EVP_PKEY_missing_parameters
  (_fun [pkey : #;const _EVP_PKEY] -> _int))
(define-crypto EVP_PKEY_copy_parameters
  (_fun [to : _EVP_PKEY] [from : #;const _EVP_PKEY] -> _int))

(define-crypto EVP_PKEY_parameters_eq
  (_fun [a : #;const _EVP_PKEY]
        [b : #;const _EVP_PKEY]
        -> [r : _int] -> (ok-result? r)))
(define-crypto EVP_PKEY_eq
  (_fun [a : #;const _EVP_PKEY]
        [b : #;const _EVP_PKEY]
        -> [r : _int] -> (ok-result? r)))

(define-crypto EVP_PKEY_get_int_param
  (_fun [pkey : #;const _EVP_PKEY]
        [key_name : #;const _bytes]
        [out : (_ptr o _int)]
        -> [r : _int] -> (and (ok-result? r) out)))

(define-crypto EVP_PKEY_get_size_t_param
  (_fun [pkey : #;const _EVP_PKEY]
        [key_name : #;const _bytes]
        [out : (_ptr o _size)]
        -> [r : _int] -> (and (ok-result? r) out)))

(define-crypto EVP_PKEY_get_bn_param
  (_fun [pkey : #;const _EVP_PKEY]
        [key_name : #;const _bytes]
        [out : (_ptr io _BIGNUM/null) = #f]
        -> [r : _int] -> (and (ok-result? r) out))
  #:wrap (allocator BN_free))

(define-crypto EVP_PKEY_get_bn_param/value
  (_fun [pkey : #;const _EVP_PKEY]
        [key_name : #;const _bytes]
        [out : (_ptr io _BIGNUM/null) = #f]
        -> [r : _int]
        -> (and (ok-result? r)
                (begin0 (BIGNUM->integer out)
                  (BN_free out))))
  #:c-id EVP_PKEY_get_bn_param)

(define-crypto EVP_PKEY_get_utf8_string_param
  (_fun [pkey : #;const _EVP_PKEY]
        [key_name : #;const _bytes]
        [out : _pointer]
        [maxlen : _size]
        [outlen : (_ptr o _size)]
        -> [r : _int] -> (and (ok-result? r) outlen)))

(define-crypto EVP_PKEY_get_octet_string_param
  (_fun [pkey : #;const _EVP_PKEY]
        [key_name : #;const _bytes]
        [out : _pointer]
        [maxlen : _size]
        [outlen : (_ptr o _size)]
        -> [r : _int] -> (and (ok-result? r) outlen)))

(define (EVP_PKEY_get_utf8_string_param/value evp key_name)
  (cond [(EVP_PKEY_get_utf8_string_param evp key_name #f 0)
         => (lambda (len)
              (define buf (make-bytes (add1 len) 0))
              (define len2 (EVP_PKEY_get_utf8_string_param evp key_name buf (add1 len)))
              (bytes->string/utf-8 buf #f 0 len2))]
        [else #f]))

(define (EVP_PKEY_get_octet_string_param/value evp key_name)
  (cond [(EVP_PKEY_get_octet_string_param evp key_name #f 0)
         => (lambda (len)
              (define buf (make-bytes len 0))
              (EVP_PKEY_get_octet_string_param evp key_name buf len)
              buf)]
        [else #f]))

;; ----------------------------------------
;; PKEY_CTX

(define-cpointer-type _EVP_PKEY_CTX)

(define-crypto EVP_PKEY_CTX_free
  (_fun [ctx : _EVP_PKEY_CTX] -> _void)
  #:wrap (deallocator))

(define-crypto EVP_PKEY_CTX_new_from_name
  (_fun [libctx : _OSSL_LIB_CTX]
        [name : #;const _nonmoving_string]
        [propq : #;const _nonmoving_string/null]
        -> _EVP_PKEY_CTX/null)
  #:wrap (allocator EVP_PKEY_CTX_free))

(define-crypto EVP_PKEY_CTX_new_from_pkey
  (_fun [libctx : _OSSL_LIB_CTX]
        [pkey : _EVP_PKEY] ;; not copied, must not GC!
        [propq : #;const _nonmoving_string/null]
        -> _EVP_PKEY_CTX/null)
  #:wrap (allocator EVP_PKEY_CTX_free))

(define-crypto EVP_PKEY_CTX_set_params
  (_fun [ctx : _EVP_PKEY_CTX]
        [params : #;const _OSSL_PARAM-array]
        -> _int))

;; ----------------------------------------
;; Validation

(define-crypto EVP_PKEY_check
  (_fun [ctx : _EVP_PKEY_CTX] -> [r : _int] -> (ok-result? r)))
(define-crypto EVP_PKEY_param_check
  (_fun [ctx : _EVP_PKEY_CTX] -> [r : _int] -> (ok-result? r)))
(define-crypto EVP_PKEY_param_check_quick
  (_fun [ctx : _EVP_PKEY_CTX] -> [r : _int] -> (ok-result? r)))
(define-crypto EVP_PKEY_public_check
  (_fun [ctx : _EVP_PKEY_CTX] -> [r : _int] -> (ok-result? r)))
(define-crypto EVP_PKEY_public_check_quick
  (_fun [ctx : _EVP_PKEY_CTX] -> [r : _int] -> (ok-result? r)))
(define-crypto EVP_PKEY_private_check
  (_fun [ctx : _EVP_PKEY_CTX] -> [r : _int] -> (ok-result? r)))
(define-crypto EVP_PKEY_pairwise_check
  (_fun [ctx : _EVP_PKEY_CTX] -> [r : _int] -> (ok-result? r)))

;; ----------------------------------------
;; Import and export components

(define-crypto EVP_PKEY_fromdata_init
  (_fun [ctx : _EVP_PKEY_CTX]
        -> [r : _int] -> (ok-result? r)))

(define-crypto EVP_PKEY_fromdata
  (_fun [ctx : _EVP_PKEY_CTX]
        [pkeyout : (_ptr io _EVP_PKEY/null) = #f]
        [selection : _int]
        [params : _OSSL_PARAM-array]
        -> [r : _int] -> (and (ok-result? r) pkeyout)))

(define-crypto EVP_PKEY_todata
  (_fun [pkey : _EVP_PKEY]
        [selection : _int]
        [params : (_ptr o _OSSL_PARAM-array)] ;; free with OSSL_PARAM_free
        -> [r : _int] -> (and (ok-result? r) params)))

(define EVP_PKEY_KEY_PARAMETERS #x84)
(define EVP_PKEY_PUBLIC_KEY     #x86)
(define EVP_PKEY_KEYPAIR        #x87)

;; ----------------------------------------
;; Encoders and Decoders

;; SubjectPublicKeyInfo

(define-crypto d2i_PUBKEY_ex
  (_fun [reuse : _pointer = #f]
        [pp : (_ptr i #;const _pointer)]
        [len : _long]
        [libctx : _OSSL_LIB_CTX]
        [propq : #;const _string]
        -> _EVP_PKEY/null)
  #:wrap (allocator EVP_PKEY_free))

(define-crypto i2d_PUBKEY
  (_fun [a : #;const _EVP_PKEY]
        [out : (_ptr io _pointer) = #f]
        -> [r : _int]
        -> (and (ok-result? r)
                (begin0 (pointer->bytes out r)
                  (CRYPTO_free out)))))

;; PrivateKeyInfo (PKCS8)

(define-cpointer-type _PKCS8_PRIV_KEY_INFO)

(define-crypto PKCS8_PRIV_KEY_INFO_free
  (_fun [a : _PKCS8_PRIV_KEY_INFO] -> _void)
  #:wrap (deallocator))

(define-crypto EVP_PKCS82PKEY_ex
  (_fun [a : #;const _PKCS8_PRIV_KEY_INFO]
        [libctx : _OSSL_LIB_CTX]
        [propq : #;const _string]
        -> _EVP_PKEY/null)
  #:wrap (allocator EVP_PKEY_free))

(define-crypto EVP_PKEY2PKCS8
  (_fun [pkey : _EVP_PKEY] -> _PKCS8_PRIV_KEY_INFO/null)
  #:wrap (allocator PKCS8_PRIV_KEY_INFO_free))

(define-crypto d2i_PKCS8_PRIV_KEY_INFO
  (_fun [reuse : _pointer = #f]
        [in : (_ptr i #;const _pointer)]
        [inlen : _long]
        -> _PKCS8_PRIV_KEY_INFO/null)
  #:wrap (allocator PKCS8_PRIV_KEY_INFO_free))

(define-crypto i2d_PKCS8_PRIV_KEY_INFO
  (_fun [a : _PKCS8_PRIV_KEY_INFO]
        [out : (_ptr io _pointer) = #f]
        -> [r : _int]
        -> (and (ok-result? r)
                (begin0 (pointer->bytes out r)
                  (CRYPTO_free out)))))

;; ----------------------------------------
;; Key Generation

(define-crypto EVP_PKEY_Q_keygen/none
  (_fun #:varargs-after 3
        [libctx : _OSSL_LIB_CTX]
        [propq : #;const _string]
        [type : #;const _string] ;; x25519, x448, ed25519, ed448, sm2
        -> _EVP_PKEY/null)
  #:c-id EVP_PKEY_Q_keygen
  #:wrap (allocator EVP_PKEY_free))

(define-crypto EVP_PKEY_Q_keygen/RSA
  (_fun #:varargs-after 3
        [libctx : _OSSL_LIB_CTX]
        [propq : #;const _string]
        [type : #;const _string = "RSA"]
        [size : _size]
        -> _EVP_PKEY/null)
  #:c-id EVP_PKEY_Q_keygen
  #:wrap (allocator EVP_PKEY_free))

(define-crypto EVP_PKEY_Q_keygen/EC
  (_fun #:varargs-after 3
        [libctx : _OSSL_LIB_CTX]
        [propq : #;const _string]
        [type : #;const _string = "EC"]
        [curve-name : _string]
        -> _EVP_PKEY/null)
  #:c-id EVP_PKEY_Q_keygen
  #:wrap (allocator EVP_PKEY_free))

(define-crypto EVP_PKEY_keygen_init
  (_fun [ctx : _EVP_PKEY_CTX] -> [r : _int] -> (ok-result? r)))
(define-crypto EVP_PKEY_paramgen_init
  (_fun [ctx : _EVP_PKEY_CTX] -> [r : _int] -> (ok-result? r)))

(define-crypto EVP_PKEY_generate
  (_fun [ctx : _EVP_PKEY_CTX]
        [pkeyout : (_ptr io _EVP_PKEY/null) = #f]
        -> [r : _int] -> (and (ok-result? r) pkeyout))
  #:wrap (allocator EVP_PKEY_free))

;; ----------------------------------------
;; Key Exchange

(define-crypto EVP_PKEY_derive_init
  (_fun [ctx : _EVP_PKEY_CTX] -> [r : _int] -> (ok-result? r)))

(define-crypto EVP_PKEY_derive_init_ex
  (_fun [ctx : _EVP_PKEY_CTX]
        [params : #;const _OSSL_PARAM-array]
        -> [r : _int] -> (ok-result? r)))

(define-crypto EVP_PKEY_derive_set_peer_ex
  (_fun [ctx : _EVP_PKEY_CTX]
        [peer : _EVP_PKEY]
        [validate_peer : _bool]
        -> [r : _int] -> (ok-result? r)))

(define-crypto EVP_PKEY_derive
  (_fun [ctx : _EVP_PKEY_CTX]
        [key : _pointer]
        [keylen : (_ptr io _size)]
        -> [r : _int] -> (and (ok-result? r) keylen)))

;; ----------------------------------------
;; Sign and Verify (low-level)

;; Typically used on already-computed digest.
;; May need cntl to set digest metadata, padding mode, etc.

(define-crypto EVP_PKEY_sign_init_ex
  (_fun [ctx : _EVP_PKEY_CTX]
        [params : #;const _OSSL_PARAM-array]
        -> [r : _int] -> (ok-result? r)))

(define-crypto EVP_PKEY_sign
  (_fun [ctx : _EVP_PKEY_CTX]
        [sig : _pointer]
        [siglen : (_ptr io _size)]
        [tbs : #;const _pointer]
        [tbslen : _size]
        -> [r : _int] -> (and (ok-result? r) siglen)))

(define-crypto EVP_PKEY_verify_init_ex
  (_fun [ctx : _EVP_PKEY_CTX]
        [params : #;const _OSSL_PARAM-array]
        -> [r : _int] -> (ok-result? r)))

(define-crypto EVP_PKEY_verify
  (_fun [ctx : _EVP_PKEY_CTX]
        [sig : #;const _pointer]
        [siglen : _size]
        [tbs : #;const _pointer]
        [tbslen : _size]
        -> [r : _int] -> (ok-result? r)))

;; ----------------------------------------
;; Digest+Sign and Digest+Verify

;; Note: the EVP_Sign* API is obsolete. Use EVP_DigestSign* instead.

(define-crypto EVP_DigestSignInit_ex
  (_fun [ctx : _EVP_MD_CTX] ;; PRE: uninit; POST: after-update
        [pctx : (_ptr io _EVP_PKEY_CTX/null) = #f]
        [mdname : #;const _string]
        [libctx : _OSSL_LIB_CTX]
        [props : #;const _string]
        [pkey : _EVP_PKEY]
        [params : #;const _OSSL_PARAM-array]
        -> [r : _int] -> (and (ok-result? r) pctx))) ;; borrowed, owned by ctx

(define-crypto EVP_DigestSign
  (_fun [ctx : _EVP_MD_CTX]
        [sigret : _pointer]
        [siglen : (_ptr io _size)]
        [tbs : _pointer]
        [tbslen : _size]
        -> [r : _int] -> (and (ok-result? r) siglen)))

(define-crypto EVP_DigestVerifyInit_ex
  (_fun [ctx : _EVP_MD_CTX]
        [pctx : (_ptr io _EVP_PKEY_CTX/null) = #f]
        [mdname : #;const _string]
        [libctx : _OSSL_LIB_CTX]
        [props : #;const _string]
        [pkey : _EVP_PKEY]
        [params : #;const _OSSL_PARAM-array]
        -> [r : _int] -> (and (ok-result? r) pctx))) ;; borrowed, owned by ctx

(define-crypto EVP_DigestVerify
  (_fun [ctx : _EVP_MD_CTX]
        [sigret : #;const _pointer]
        [siglen : _size]
        [tbs : #;const _pointer]
        [tbslen : _size]
        -> [r : _int] -> (ok-result? r)))

;; ----------------------------------------
;; Encryption and Decryption

(define-crypto EVP_PKEY_encrypt_init_ex
  (_fun [ctx : _EVP_PKEY_CTX]
        [params : #;const _OSSL_PARAM-array]
        -> [r : _int] -> (ok-result? r)))

(define-crypto EVP_PKEY_encrypt
  (_fun [ctx : _EVP_PKEY_CTX]
        [out : _pointer]
        [outlen : (_ptr io _size)]
        [in : #;const _pointer]
        [inlen : _size]
        -> [r : _int] -> (and (ok-result? r) outlen)))

(define-crypto EVP_PKEY_decrypt_init_ex
  (_fun [ctx : _EVP_PKEY_CTX]
        [params : #;const _OSSL_PARAM-array]
        -> [r : _int] -> (ok-result? r)))

(define-crypto EVP_PKEY_decrypt
  (_fun [ctx : _EVP_PKEY_CTX]
        [out : _pointer]
        [outlen : (_ptr io _size)]
        [in : #;const _pointer]
        [inlen : _size]
        -> [r : _int] -> (and (ok-result? r) outlen)))

;; ----------------------------------------
;; Key Encapsulation

(define-crypto EVP_PKEY_encapsulate_init
  (_fun [ctx : _EVP_PKEY_CTX]
        [params : #;const _OSSL_PARAM-array]
        -> [r : _int] -> (ok-result? r)))

(define-crypto EVP_PKEY_encapsulate
  (_fun [ctx : _EVP_PKEY_CTX]
        [wrappedkey : _pointer]
        [wrappedlen : (_ptr io _size)]
        [plainkey : _pointer]
        [plainlen : (_ptr io _size)]
        -> [r : _int] -> (and (ok-result? r) (cons wrappedlen plainlen))))

(define-crypto EVP_PKEY_decapsulate_init
  (_fun [ctx : _EVP_PKEY_CTX]
        [params : #;const _OSSL_PARAM-array]
        -> [r : _int] -> (ok-result? r)))

(define-crypto EVP_PKEY_decapsulate
  (_fun [ctx : _EVP_PKEY_CTX]
        [unwrappedkey : _pointer]
        [unwrappedlen : (_ptr io _size)]
        [wrappedkey : #;const _pointer]
        [wrappedlen : _size]
        -> [r : _int] -> (and (ok-result? r) unwrappedlen)))
