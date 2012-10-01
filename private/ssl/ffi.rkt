;; FFI bindings for libcrypto
;;
;; Copyright 2012 Ryan Culpepper
;; (C) Copyright 2007-2009 Dimitris Vyzovitis <vyzo at media.mit.edu>
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
         ffi/unsafe/define
         ffi/unsafe/alloc
         ffi/unsafe/atomic
         openssl/libcrypto)
(provide (protect-out (all-defined-out)))

;; ============================================================
;; Library initialization & error-catching wrappers

(define-ffi-definer define-crypto libcrypto
  #:default-make-fail make-not-available)

(let ()
  (define-crypto ERR_load_crypto_strings (_fun -> _void))
  (define-crypto OpenSSL_add_all_ciphers (_fun -> _void))
  (define-crypto OpenSSL_add_all_digests (_fun -> _void))
  (ERR_load_crypto_strings)
  (OpenSSL_add_all_ciphers)
  (OpenSSL_add_all_digests))

;; ----

(define-crypto ERR_get_error
  (_fun -> _ulong))
(define-crypto ERR_peek_last_error
  (_fun -> _ulong))
(define-crypto ERR_lib_error_string
  (_fun _ulong -> _string))
(define-crypto ERR_func_error_string
  (_fun _ulong -> _string))
(define-crypto ERR_reason_error_string
  (_fun _ulong -> _string))

;; Use atomic wrapper around ffi calls to avoid race retrieving error info.

(define (err-wrap who ok? [convert values])
  (lambda (proc)
    (lambda args
      (call-as-atomic
       (lambda ()
         (let ([result (apply proc args)])
           (if (ok? result)
               (convert result)
               (raise-crypto-error who))))))))

(define (err-wrap/check who)
  (err-wrap who positive? void))

(define (err-wrap/pointer who)
  (err-wrap who values))

(define (raise-crypto-error where (info #f))
  (let* ([e (ERR_get_error)]
         [le (ERR_lib_error_string e)]
         [fe (and le (ERR_func_error_string e))]
         [re (and fe (ERR_reason_error_string e))])
    (error where "~a [~a:~a:~a]~a~a"
           (or (ERR_reason_error_string e) "?")
           (or (ERR_lib_error_string e) "?")
           (or (ERR_func_error_string e) "?")
           e
           (if info " " "")
           (or info ""))))

;; ============================================================
;; Bignum

(define-cpointer-type _BIGNUM)

(define-crypto BN_free
  (_fun _BIGNUM
        -> _void)
  #:wrap (deallocator))

(define-crypto BN_new
  (_fun -> _BIGNUM/null)
  #:wrap (compose (allocator BN_free) (err-wrap/pointer 'BN_new)))

(define-crypto BN_add_word
  (_fun _BIGNUM
        _ulong
        -> _int)
  #:wrap (err-wrap/check 'BN_add_word))

(define-crypto BN_num_bits
  (_fun _BIGNUM -> _int))

(define-crypto BN_bn2bin
  (_fun _BIGNUM _bytes -> _int))

(define-crypto BN_bin2bn
  (_fun (bs : _bytes)
        (_int = (bytes-length bs))
        (_pointer = #f)
        -> _BIGNUM/null)
  #:wrap (compose (allocator BN_free) (err-wrap/pointer 'BN_bin2bn)))

;; ============================================================
;; Digest

(define-cpointer-type _EVP_MD_CTX)
(define-cpointer-type _EVP_MD)
(define-cpointer-type _HMAC_CTX)
(define EVP_MAX_MD_SIZE 64) ;; 512 bits

(define-crypto EVP_MD_CTX_destroy
  (_fun _EVP_MD_CTX -> _void)
  #:wrap (deallocator))

(define-crypto EVP_MD_CTX_create
  (_fun -> _EVP_MD_CTX/null)
  #:wrap (compose (allocator EVP_MD_CTX_destroy) (err-wrap/pointer 'EVP_MD_CTX_create)))

(define-crypto EVP_get_digestbyname
  (_fun _string -> _EVP_MD/null))

(define-crypto EVP_DigestInit_ex
  (_fun _EVP_MD_CTX
        _EVP_MD
        (_pointer = #f)
        -> _int)
  #:wrap (err-wrap/check 'EVP_DigestInit_ex))

(define-crypto EVP_DigestUpdate
  (_fun _EVP_MD_CTX
        (d : _pointer)
        (cnt : _ulong)
        -> _int)
  #:wrap (err-wrap/check 'EVP_DigestUpdate))

(define-crypto EVP_DigestFinal_ex
  (_fun _EVP_MD_CTX
        (out : _pointer)
        (_pointer = #f)
        -> _int)
  #:wrap (err-wrap/check 'EVP_DigestFinal_ex))

(define-crypto EVP_MD_CTX_copy_ex
  (_fun _EVP_MD_CTX
        _EVP_MD_CTX
        -> _int)
  #:wrap (err-wrap/check 'EVP_MD_CTX_copy_ex))

(define-crypto HMAC
  (_fun _EVP_MD
        (key : _pointer)
        (keylen : _int)
        (d : _pointer)
        (n : _int)
        (md : _pointer)
        (r : (_ptr o _uint))
        -> _void
        -> r))

;; ugh - no HMAC_CTX* maker in libcrypto
(define HMAC_CTX_free
  ((deallocator)
   (lambda (p)
     (HMAC_CTX_cleanup p)
     (free p))))
(define HMAC_CTX_new
  ((allocator HMAC_CTX_free)
   ((err-wrap/pointer 'HMAC_CTX_new)
    (lambda ()
      (let ([hmac (malloc 'raw 256)]) ;; FIXME: check size
        (cpointer-push-tag! hmac HMAC_CTX-tag)
        (HMAC_CTX_init hmac)
        hmac)))))

(define-crypto HMAC_CTX_init
  (_fun _HMAC_CTX -> _void))

(define-crypto HMAC_CTX_cleanup
  (_fun _HMAC_CTX -> _void))

(define-crypto HMAC_Init_ex
  (_fun _HMAC_CTX
        (key : _pointer)
        (keylen : _uint)
        _EVP_MD
        (_pointer = #f)
        -> _void) ;; _int since OpenSSL 1.0.0
  #| #:wrap (err-wrap/check 'HMAC_Init_ex) |#)

(define-crypto HMAC_Update
  (_fun _HMAC_CTX
        (data : _pointer)
        (len : _uint)
        -> _void) ;; _int since OpenSSL 1.0.0
  #| #:wrap (err-wrap/check 'HMAC_Update) |#)

(define-crypto HMAC_Final
  (_fun _HMAC_CTX
        (md : _pointer)
        (r : (_ptr o _int))
        -> _void ;; _int since OpenSSL 1.0.0
        -> r)
  #| #:wrap (err-wrap 'HMAC_Final values) |#)

;; ============================================================
;; Cipher

(define-cpointer-type _EVP_CIPHER_CTX)
(define-cpointer-type _EVP_CIPHER)

;; libcrypto < 0.9.8.d doesn't have EVP_CIPHER_CTX_new/free
(define-crypto EVP_CIPHER_CTX_free
  (_fun _EVP_CIPHER_CTX -> _void)
  #:wrap (deallocator))
(define-crypto EVP_CIPHER_CTX_new
  (_fun -> _EVP_CIPHER_CTX/null)
  #:wrap (compose (allocator EVP_CIPHER_CTX_free) (err-wrap/pointer 'EVP_CIPHER_CTX_new)))

(define-crypto EVP_CIPHER_CTX_cleanup
  (_fun _EVP_CIPHER_CTX -> _void)
  #:wrap (err-wrap/check 'EVP_CIPHER_CTX_cleanup))

(define-crypto EVP_CipherInit_ex
  (_fun _EVP_CIPHER_CTX
        _EVP_CIPHER
        (_pointer = #f)
        (key : _pointer)
        (iv : _pointer)
        (enc? : _bool)
        -> _int)
  #:wrap (err-wrap/check 'EVP_CipherInit_ex))

(define-crypto EVP_CipherUpdate
  (_fun _EVP_CIPHER_CTX
        (out : _pointer)
        (olen : (_ptr o _int))
        (in : _pointer)
        (ilen : _int)
        -> (result : _int)
        -> (and (= result 1) ;; okay
                olen))
  #:wrap (err-wrap 'EVP_CipherUpdate values))

(define-crypto EVP_CipherFinal_ex
  (_fun _EVP_CIPHER_CTX
        (out : _pointer)
        (olen : (_ptr o _int))
        -> (result : _int)
        -> (and (= result 1) ;; okay
                olen))
  #:wrap (err-wrap 'EVP_CipherFinal_ex values))

(define-crypto EVP_CIPHER_CTX_set_padding
  (_fun _EVP_CIPHER_CTX
        _bool
        -> _int)
  #:wrap (err-wrap/check 'EVP_CIPHER_CTX_set_padding))

;; ============================================================
;; Diffie-Hellman

(define-cpointer-type _DH)

(define-crypto DH_free
  (_fun _DH -> _void)
  #:wrap (deallocator))

(define-crypto DH_new
  (_fun -> _DH/null)
  #:wrap (allocator DH_free))

(define-crypto DH_size
  (_fun _DH -> _int))

(define-crypto DH_generate_key
  (_fun _DH -> _int)
  #:wrap (err-wrap/check 'DH_generate_key))

(define-crypto DH_compute_key
  (_fun _pointer
        _BIGNUM
        _DH
        -> _int)
  #:wrap (err-wrap/check 'DH_compute_key))

(define-crypto d2i_DHparams
  (_fun (_pointer = #f)
        (_ptr i _pointer)
        _long
        -> (result : _DH/null))
  #:wrap (compose (allocator DH_free) (err-wrap/pointer 'd2i_DHparams)))

;; ============================================================
;; Public-Key Cryptography

(define-cpointer-type _EVP_PKEY)
(define-cpointer-type _RSA)
(define-cpointer-type _DSA)

(define-crypto EVP_PKEY_free
  (_fun _EVP_PKEY -> _void)
  #:wrap (deallocator))

(define-crypto EVP_PKEY_new
  (_fun -> _EVP_PKEY/null)
  #:wrap (compose (allocator EVP_PKEY_free) (err-wrap/pointer 'EVP_PKEY_new)))

(define-crypto RSA_free
  (_fun _RSA -> _void)
  #:wrap (deallocator))

(define-crypto RSA_new
  (_fun -> _RSA/null)
  #:wrap (compose (allocator RSA_free) (err-wrap/pointer 'RSA_new)))

(define-crypto DSA_free
  (_fun _DSA -> _void)
  #:wrap (deallocator))

(define-crypto DSA_new
  (_fun -> _DSA/null)
  #:wrap (compose (allocator DSA_free) (err-wrap/pointer 'DSA_new)))

(define-crypto EVP_PKEY_type
  (_fun _int -> _int)
  #:wrap (err-wrap 'EVP_PKEY_type positive?))

(define-crypto EVP_PKEY_size
  (_fun _EVP_PKEY -> _int)
  #:wrap (err-wrap 'EVP_PKEY_size positive?))

(define-crypto EVP_PKEY_bits
  (_fun _EVP_PKEY -> _int)
  #:wrap (err-wrap 'EVP_PKEY_bits positive?))

(define-crypto EVP_PKEY_set1_RSA
  (_fun _EVP_PKEY _RSA -> _int)
  #:wrap (err-wrap/check 'EVP_PKEY_set1_RSA))

(define-crypto EVP_PKEY_set1_DSA
  (_fun _EVP_PKEY _DSA -> _int)
  #:wrap (err-wrap/check 'EVP_PKEY_set1_DSA))

(define-crypto EVP_SignFinal
  (_fun _EVP_MD_CTX
        (sig : _pointer)
        (count : (_ptr o _uint))
        _EVP_PKEY
        -> (result : _int)
        -> (and (= result 1) count))
  #:wrap (err-wrap 'EVP_SignFinal values))

(define-crypto EVP_VerifyFinal
  (_fun _EVP_MD_CTX (buf : _pointer) (len : _uint) _EVP_PKEY -> _int)
  #:wrap (err-wrap 'EVP_VerifyFinal
                   (lambda (r) (member r '(0 1)))
                   (lambda (r) (case r ((0) #f) ((1) #t)))))

(define-crypto EVP_PKEY_cmp
  (_fun _EVP_PKEY _EVP_PKEY -> _int)
  #:wrap (err-wrap 'EVP_PKEY_cmp
                   (lambda (r) (member r '(0 1)))
                   (lambda (r) (case r ((0) #f) ((1) #t)))))

(define-crypto EVP_PKEY_encrypt
  (_fun _pointer _pointer _int _EVP_PKEY -> _int)
  #:wrap (err-wrap 'EVP_PKEY_encrypt exact-nonnegative-integer?))

(define-crypto EVP_PKEY_decrypt
  (_fun _pointer _pointer _int _EVP_PKEY -> _int)
  #:wrap (err-wrap 'EVP_PKEY_decrypt exact-nonnegative-integer?))

(define-crypto RSA_generate_key_ex
  (_fun _RSA _int _BIGNUM (_pointer = #f) -> _int)
  #:wrap (err-wrap/check 'RSA_generate_key_ex))

(define-crypto DSA_generate_parameters_ex
  (_fun _DSA _int
        (_pointer = #f) (_int = 0) (_pointer = #f) (_pointer = #f) (_pointer = #f)
        -> _int)
  #:wrap (err-wrap/check 'DSA_generate_parameters_ex))

(define-crypto DSA_generate_key
  (_fun _DSA -> _int)
  #:wrap (err-wrap/check 'DSA_generate_key))

(define-crypto d2i_PublicKey
  (_fun _int (_pointer = #f) (_ptr i _pointer) _long -> _EVP_PKEY/null)
  #:wrap (compose (allocator EVP_PKEY_free) (err-wrap/pointer 'd2i_PublicKey)))

(define-crypto d2i_PrivateKey
  (_fun _int (_pointer = #f) (_ptr i _pointer) _long -> _EVP_PKEY/null)
  #:wrap (compose (allocator EVP_PKEY_free) (err-wrap/pointer 'd2i_PrivateKey)))

(define-crypto i2d_PublicKey
  (_fun _EVP_PKEY (_ptr i _pointer) -> _int)
  #:wrap (err-wrap 'i2d_PublicKey positive?))

(define-crypto i2d_PrivateKey
  (_fun _EVP_PKEY (_ptr i _pointer) -> _int)
  #:wrap (err-wrap 'i2d_PrivateKey positive?))

(define-values (i2d_PublicKey-length i2d_PrivateKey-length)
  (let ()
    (define-crypto i2d_PublicKey (_fun _EVP_PKEY (_pointer = #f) -> _int)
      #:wrap (err-wrap 'i2d_PublicKey-length positive?))
    (define-crypto i2d_PrivateKey (_fun _EVP_PKEY (_pointer = #f) -> _int)
      #:wrap (err-wrap 'i2d_PrivateKey-length positive?))
    (values i2d_PublicKey i2d_PrivateKey)))

;; ============================================================
;; Random Numbers

(define-crypto RAND_bytes
  (_fun (buf : _pointer)
        (len : _uint)
        -> _int)
  #:wrap (err-wrap/check 'RAND_bytes))

(define-crypto RAND_pseudo_bytes
  (_fun (buf : _pointer)
        (len : _uint)
        -> _int)
  #:wrap (err-wrap/check 'RAND_pseudo_bytes))
