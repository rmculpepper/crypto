;; Copyright 2012 Ryan Culpepper
;; Copyright 2007-2009 Dimitris Vyzovitis <vyzo at media.mit.edu>
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

(define-crypto EVP_get_digestbyname
  (_fun _string -> _EVP_MD/null))

(define-crypto EVP_MD_do_all_sorted
  (_fun (_fun _EVP_MD/null _string _string #| _pointer |# -> _void)
        (_pointer = #f)
        -> _void))

(define-crypto EVP_MD_size (_fun _EVP_MD -> _int))
(define-crypto EVP_MD_block_size (_fun _EVP_MD -> _int))

(define-crypto EVP_MD_CTX_destroy
  (_fun _EVP_MD_CTX -> _void)
  #:wrap (deallocator))

(define-crypto EVP_MD_CTX_create
  (_fun -> _EVP_MD_CTX/null)
  #:wrap (compose (allocator EVP_MD_CTX_destroy) (err-wrap/pointer 'EVP_MD_CTX_create)))

(define-crypto EVP_DigestInit_ex
  (_fun _EVP_MD_CTX
        _EVP_MD
        (_pointer = #f)
        -> _int)
  #:wrap (err-wrap/check 'EVP_DigestInit_ex))

(define-crypto EVP_DigestUpdate
  (_fun _EVP_MD_CTX
        (d : _pointer)
        (cnt : _size)
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
      (let ([hmac (malloc 'raw 300)]) ;; sizeof(HMAC_CTX) = 288 on linux-x86_64
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

(define-crypto PKCS5_PBKDF2_HMAC
  (_fun (input digest salt iter outlen) ::
        (input    : _bytes)
        (inlen    : _int = (bytes-length input))
        (salt     : _bytes)
        (saltlen  : _int = (bytes-length salt))
        (iter     : _int)
        (digest   : _EVP_MD)
        (outlen   : _int)
        (out      : (_bytes o outlen))
        -> (r : _int)
        -> (values r out)))

;; ============================================================
;; Cipher

(define-cpointer-type _EVP_CIPHER_CTX)
(define-cpointer-type _EVP_CIPHER)

(define-crypto EVP_get_cipherbyname
  (_fun _string -> _EVP_CIPHER/null))

(define-crypto EVP_CIPHER_do_all_sorted
  (_fun (_fun _EVP_CIPHER/null _string _string #| _pointer |# -> _void)
        (_pointer = #f)
        -> _void))

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

(define-crypto EVP_CIPHER_CTX_set_key_length
  (_fun _EVP_CIPHER_CTX _int -> _int)
  #:wrap (err-wrap/check 'EVP_CIPHER_CTX_set_key_length))

(define-crypto EVP_CIPHER_CTX_ctrl
  (_fun _EVP_CIPHER_CTX _int _int _bytes -> _int)
  #:wrap (err-wrap/check 'EVP_CIPHER_CTX_ctrl))

(define-crypto EVP_CIPHER_CTX_set_padding
  (_fun _EVP_CIPHER_CTX _bool -> _int)
  #:wrap (err-wrap/check 'EVP_CIPHER_CTX_set_padding))

;; ============================================================
;; Diffie-Hellman

(define-cpointer-type _DH)

(define-crypto DH_free
  (_fun _DH -> _void)
  #:wrap (deallocator))

(define-crypto DH_new
  (_fun -> _DH/null)
  #:wrap (compose (allocator DH_free) (error-wrap/pointer 'DH_new)))

(define-crypto DHparams_dup
  (_fun _DH -> _DH))

(define-crypto DH_size
  (_fun _DH -> _int))

(define-crypto DH_generate_parameters_ex
  (_fun _DH _int _int (_fpointer = #f) -> _int)
  #:wrap (err-wrap/check 'DH_generate_parameters_ex))

;; PKCS#3 DH params
(define-crypto i2d_DHparams
  (_fun _DH (_ptr i _pointer) -> _int)
  #:wrap (err-wrap 'i2d_DHparams positive?))
(define-crypto d2i_DHparams
  (_fun (_pointer = #f) (_ptr i _pointer) _long -> _DH/null)
  #:wrap (compose (allocator DH_free) (err-wrap/pointer 'd2i_DHparams)))

(define-crypto DH_check   ;; -> #t, or flags for failure
  (_fun _DH (codes : (_ptr o _int))
        -> (status : _int)
        -> (or (positive? status)
               codes)))

(define-crypto DH_generate_key
  (_fun _DH -> _int)
  #:wrap (err-wrap/check 'DH_generate_key))

(define-crypto DH_compute_key
  (_fun (dh pub) ::
        (secret : _pointer = (make-bytes (DH_size dh)))
        (pub : _BIGNUM)
        (dh : _DH)
        -> (status : _int)
        -> (and (positive? status) secret))
  #:wrap (err-wrap 'DH_compute_key values))

(define-crypto d2i_DHparams
  (_fun (_pointer = #f)
        (_ptr i _pointer)
        _long
        -> (result : _DH/null))
  #:wrap (compose (allocator DH_free) (err-wrap/pointer 'd2i_DHparams)))

;; ============================================================
;; Public-Key Cryptography

(define-cpointer-type _EVP_PKEY)
(define-cpointer-type _EVP_PKEY_CTX)
(define-cpointer-type _RSA)
(define-cpointer-type _DSA)

(define EVP_PKEY_RSA	6)
(define EVP_PKEY_DSA	116)

(define-crypto EVP_PKEY_free
  (_fun _EVP_PKEY -> _void)
  #:wrap (deallocator))

(define-crypto EVP_PKEY_new
  (_fun -> _EVP_PKEY/null)
  #:wrap (compose (allocator EVP_PKEY_free) (err-wrap/pointer 'EVP_PKEY_new)))

(define-crypto EVP_PKEY_CTX_free
  (_fun _EVP_PKEY_CTX -> _void)
  #:wrap (deallocator))

(define-crypto EVP_PKEY_CTX_new
  (_fun _EVP_PKEY (_pointer = #f) -> _EVP_PKEY_CTX)
  #:wrap (compose (allocator EVP_PKEY_CTX_free) (err-wrap/pointer 'EVP_Pkey_CTX_new)))

(define-crypto EVP_PKEY_CTX_new_id
  (_fun _int (_pointer = #f) -> _EVP_PKEY_CTX)
  #:wrap (compose (allocator EVP_PKEY_CTX_free) (err-wrap/pointer 'EVP_Pkey_CTX_new_id)))

(define-crypto EVP_PKEY_CTX_set_cb
  (_fun _EVP_PKEY_CTX _fpointer -> _void))

(define-crypto EVP_PKEY_keygen_init
  (_fun _EVP_PKEY_CTX -> _int)
  #:wrap (err-wrap 'EVP_PKEY_keygen_init positive?))

(define-crypto EVP_PKEY_paramgen_init
  (_fun _EVP_PKEY_CTX -> _int)
  #:wrap (err-wrap 'EVP_PKEY_paramgen_init positive?))

(define-crypto EVP_PKEY_CTX_ctrl
  (_fun _EVP_PKEY_CTX
        (keytype : _int)
        (optype : _int)
        (cmd : _int)
        (p1 : _int)
        (p2 : _pointer)
        -> _int)
  #:wrap (err-wrap 'EVP_PKEY_CTX_ctrl positive?))

(define (EVP_PKEY_CTX_set_signature_md ctx md)
  (EVP_PKEY_CTX_ctrl ctx  -1 EVP_PKEY_OP_TYPE_SIG
                     EVP_PKEY_CTRL_MD 0 md))

(define (EVP_PKEY_CTX_set_rsa_padding ctx pad)
  (EVP_PKEY_CTX_ctrl ctx EVP_PKEY_RSA -1 EVP_PKEY_CTRL_RSA_PADDING pad #f))
(define (EVP_PKEY_CTX_set_rsa_pss_saltlen ctx len)
  (EVP_PKEY_CTX_ctrl ctx EVP_PKEY_RSA
                     (bitwise-ior EVP_PKEY_OP_SIGN EVP_PKEY_OP_VERIFY)
                     EVP_PKEY_CTRL_RSA_PSS_SALTLEN
                     len
                     #f))
(define (EVP_PKEY_CTX_set_rsa_keygen_bits ctx bits)
  (EVP_PKEY_CTX_ctrl ctx EVP_PKEY_RSA EVP_PKEY_OP_KEYGEN
                     EVP_PKEY_CTRL_RSA_KEYGEN_BITS bits #f))
(define (EVP_PKEY_CTX_set_rsa_keygen_pubexp ctx pubexp)
  (EVP_PKEY_CTX_ctrl ctx EVP_PKEY_RSA EVP_PKEY_OP_KEYGEN
                     EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP 0 pubexp))
;;(define (EVP_PKEY_CTX_set_rsa_mgf1_md ctx md)
;;  (EVP_PKEY_CTX_ctrl ctx EVP_PKEY_RSA EVP_PKEY_OP_TYPE_SIG
;;                     EVP_PKEY_CTRL_RSA_MGF1_MD 0 md))

(define EVP_PKEY_OP_PARAMGEN            (arithmetic-shift 1 1))
(define EVP_PKEY_OP_KEYGEN              (arithmetic-shift 1 2))
(define EVP_PKEY_OP_SIGN                (arithmetic-shift 1 3))
(define EVP_PKEY_OP_VERIFY              (arithmetic-shift 1 4))
(define EVP_PKEY_OP_VERIFYRECOVER       (arithmetic-shift 1 5))
(define EVP_PKEY_OP_SIGNCTX             (arithmetic-shift 1 6))
(define EVP_PKEY_OP_VERIFYCTX           (arithmetic-shift 1 7))

(define EVP_PKEY_OP_TYPE_SIG
  (bitwise-ior EVP_PKEY_OP_SIGN EVP_PKEY_OP_VERIFY EVP_PKEY_OP_VERIFYRECOVER
               EVP_PKEY_OP_SIGNCTX EVP_PKEY_OP_VERIFYCTX))

(define EVP_PKEY_CTRL_MD                1)
(define EVP_PKEY_ALG_CTRL               #x1000)
(define EVP_PKEY_CTRL_RSA_PADDING       (+ EVP_PKEY_ALG_CTRL 1))
(define EVP_PKEY_CTRL_RSA_PSS_SALTLEN   (+ EVP_PKEY_ALG_CTRL 2))
(define EVP_PKEY_CTRL_RSA_KEYGEN_BITS   (+ EVP_PKEY_ALG_CTRL 3))
(define EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP (+ EVP_PKEY_ALG_CTRL 4))
(define EVP_PKEY_CTRL_RSA_MGF1_MD       (+ EVP_PKEY_ALG_CTRL 5))
(define EVP_PKEY_CTRL_GET_RSA_PADDING           (+ EVP_PKEY_ALG_CTRL 6))
(define EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN       (+ EVP_PKEY_ALG_CTRL 7))
(define EVP_PKEY_CTRL_GET_RSA_MGF1_MD           (+ EVP_PKEY_ALG_CTRL 8))

(define RSA_PKCS1_PADDING       1)
(define RSA_NO_PADDING          3)
(define RSA_PKCS1_OAEP_PADDING  4)
(define RSA_PKCS1_PSS_PADDING   6)

(define (EVP_PKEY_CTX_set_dsa_paramgen_bits ctx nbits)
  (EVP_PKEY_CTX_ctrl ctx EVP_PKEY_DSA EVP_PKEY_OP_PARAMGEN
                     EVP_PKEY_CTRL_DSA_PARAMGEN_BITS nbits #f))

(define EVP_PKEY_CTRL_DSA_PARAMGEN_BITS         (+ EVP_PKEY_ALG_CTRL 1))
(define EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS       (+ EVP_PKEY_ALG_CTRL 2))
(define EVP_PKEY_CTRL_DSA_PARAMGEN_MD           (+ EVP_PKEY_ALG_CTRL 3))

(define-crypto EVP_PKEY_keygen
  (_fun _EVP_PKEY_CTX
        (result : (_ptr o _EVP_PKEY/null))
        -> (status : _int)
        -> (and (> status 0) result))
  #:wrap (compose (allocator EVP_PKEY_free) (err-wrap/pointer 'EVP_PKEY_keygen)))

(define-crypto EVP_PKEY_paramgen
  (_fun _EVP_PKEY_CTX
        (result : (_ptr o _EVP_PKEY/null))
        -> (status : _int)
        -> (and (> status 0) result))
  #:wrap (compose (allocator EVP_PKEY_free) (err-wrap/pointer 'EVP_PKEY_paramgen)))

(define-crypto EVP_PKEY_copy_parameters
  (_fun _EVP_PKEY _EVP_PKEY -> _int)
  #:wrap (err-wrap 'EVP_PKEY_copy_parameters positive?))

(define-crypto EVP_PKEY_cmp_parameters
  (_fun _EVP_PKEY _EVP_PKEY -> _int)
  #:wrap (err-wrap 'EVP_PKEY_cmp
                   (lambda (r) (member r '(0 1)))
                   (lambda (r) (case r ((0) #f) ((1) #t)))))



(define-crypto RSA_free
  (_fun _RSA -> _void)
  #:wrap (deallocator))

(define-crypto RSA_new
  (_fun -> _RSA/null)
  #:wrap (compose (allocator RSA_free) (err-wrap/pointer 'RSA_new)))

(define-crypto RSA_generate_key_ex
  (_fun _RSA _int _BIGNUM/null _fpointer -> _int)
  #:wrap (err-wrap 'RSA_generate_key_ex positive?))

(define-crypto DSA_free
  (_fun _DSA -> _void)
  #:wrap (deallocator))

(define-crypto DSA_new
  (_fun -> _DSA/null)
  #:wrap (compose (allocator DSA_free) (err-wrap/pointer 'DSA_new)))

(define-crypto DSA_generate_parameters_ex
  (_fun _DSA _int (_pointer = #f) (_int = 0) (_pointer = #f) (_pointer = #f) (_fpointer = #f)
        -> _int)
  #:wrap (err-wrap 'DSA_generate_parameters_ex positive?))

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

(define-crypto EVP_PKEY_get1_RSA
  (_fun _EVP_PKEY -> _RSA/null)
  #:wrap (compose (allocator RSA_free) (err-wrap/pointer 'EVP_PKEY_get1_RSA)))

(define-crypto EVP_PKEY_get1_DSA
  (_fun _EVP_PKEY -> _DSA/null)
  #:wrap (compose (allocator DSA_free) (err-wrap/pointer 'EVP_PKEY_get1_DSA)))

(define-crypto EVP_PKEY_sign_init
  (_fun _EVP_PKEY_CTX -> _int)
  #:wrap (err-wrap 'EVP_PKEY_sign_init positive?))

(define-crypto EVP_PKEY_sign
  (_fun _EVP_PKEY_CTX _pointer (siglen : (_ptr io _size)) _pointer _size
        -> (status : _int)
        -> (if (positive? status) siglen status))
  #:wrap (err-wrap 'EVP_PKEY_sign positive?))

(define-crypto EVP_PKEY_verify_init
  (_fun _EVP_PKEY_CTX -> _int)
  #:wrap (err-wrap 'EVP_PKEY_verify_init positive?))

(define-crypto EVP_PKEY_verify
  (_fun _EVP_PKEY_CTX _pointer _size _pointer _size -> _int)
  #:wrap (err-wrap 'EVP_PKEY_verify
                   (lambda (r) (member r '(0 1)))
                   (lambda (r) (case r ((0) #f) ((1) #t)))))

(define-crypto EVP_PKEY_encrypt_init
  (_fun _EVP_PKEY_CTX -> _int)
  #:wrap (err-wrap 'EVP_PKEY_encrypt_init positive?))

(define-crypto EVP_PKEY_encrypt
  (_fun _EVP_PKEY_CTX _pointer (outlen : (_ptr io _size)) _pointer _size
        -> (status : _int)
        -> (if (positive? status) outlen status))
  #:wrap (err-wrap 'EVP_PKEY_encrypt positive?))

(define-crypto EVP_PKEY_decrypt_init
  (_fun _EVP_PKEY_CTX -> _int)
  #:wrap (err-wrap 'EVP_PKEY_decrypt_init positive?))

(define-crypto EVP_PKEY_decrypt
  (_fun _EVP_PKEY_CTX _pointer (outlen : (_ptr io _size)) _pointer _size
        -> (status : _int)
        -> (if (positive? status) outlen status))
  #:wrap (err-wrap 'EVP_PKEY_decrypt positive?))

(define-crypto EVP_PKEY_cmp
  (_fun _EVP_PKEY _EVP_PKEY -> _int)
  #:wrap (err-wrap 'EVP_PKEY_cmp
                   (lambda (r) (member r '(0 1)))
                   (lambda (r) (case r ((0) #f) ((1) #t)))))

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

(define-crypto d2i_DSAparams
  (_fun (_pointer = #f) (_ptr i _pointer) _long -> _DSA/null)
  #:wrap (compose (allocator DSA_free) (err-wrap/pointer 'd2i_DSAparams)))

(define-crypto i2d_DSAparams
  (_fun _DSA (_ptr i _pointer) -> _int)
  #:wrap (err-wrap 'i2d_DSAparams positive?))


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
