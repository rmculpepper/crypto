;; Copyright 2012-2018 Ryan Culpepper
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
         openssl/libcrypto
         "../common/error.rkt")
(provide (protect-out (all-defined-out))
         libcrypto)

(define ((K v) . args) v)

;; ============================================================
;; Library initialization & error-catching wrappers

(define-ffi-definer define-crypto libcrypto
  #:default-make-fail make-not-available)
(define libcrypto-load-error libcrypto-load-fail-reason)

(define-crypto SSLeay (_fun -> _long) #:fail (K (K #f)))
(define-crypto OpenSSL_version_num (_fun -> _long) #:fail (K SSLeay))

(define libcrypto-ok?
  (let ([v (or (OpenSSL_version_num) 0)])
    ;; at least version 1.0.0 (MNNFFPPS)
    (>= v #x10000000)))

(let ()
  (define-crypto ERR_load_crypto_strings (_fun -> _void) #:fail (K void))
  (define-crypto OpenSSL_add_all_ciphers (_fun -> _void) #:fail (K void))
  (define-crypto OpenSSL_add_all_digests (_fun -> _void) #:fail (K void))
  (ERR_load_crypto_strings)
  (OpenSSL_add_all_ciphers)
  (OpenSSL_add_all_digests))

(define-crypto CRYPTO_free
  (_fun _pointer -> _void))

;; ----

(define-crypto ERR_get_error
  (_fun -> _ulong))
(define-crypto ERR_peek_error
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

(define (err-wrap who [ok? positive?] #:convert [convert values] #:drain? [drain? #f])
  (lambda (proc)
    (lambda args
      (call-as-atomic
       (lambda ()
         (let ([result (apply proc args)])
           (cond [(ok? result)
                  (let ([errors (drain-errors)])
                    (unless drain?
                      (report-errors who errors)))
                  (convert result)]
                 [else (raise-crypto-error who)])))))))

(define (drain-errors)
  (let ([e (ERR_get_error)])
    (cond [(zero? e) null]
          [else (cons e (drain-errors))])))

(define (report-errors who errors)
  (when (pair? errors)
    (call-as-nonatomic
     (lambda ()
       (for ([e (in-list errors)])
         (eprintf "~a: internal error: unhandled error\n ~a [~a:~a:~a]\n"
                  who
                  (or (ERR_reason_error_string e) "?")
                  (or (ERR_lib_error_string e) "?")
                  (or (ERR_func_error_string e) "?")
                  e))))))

(define (err-wrap/pointer who)
  (err-wrap who values))

(define (raise-crypto-error where)
  (let ([e (ERR_get_error)])
    (drain-errors)
    (crypto-error "~a: ~a [~a:~a:~a]"
                  where
                  (or (ERR_reason_error_string e) "?")
                  (or (ERR_lib_error_string e) "?")
                  (or (ERR_func_error_string e) "?")
                  e)))

(define (i2d i2d_Type x)
  (define outlen (i2d_Type x #f))
  (define outbuf (make-bytes outlen 0))
  (define outlen2 (i2d_Type x outbuf))
  (if (< outlen2 outlen)
      (subbytes outbuf 0 outlen2)
      outbuf))

(define-crypto OBJ_nid2sn
  (_fun _int -> _string/utf-8))
(define-crypto OBJ_nid2ln
  (_fun _int -> _string/utf-8))
(define-crypto OBJ_sn2nid
  (_fun _string/utf-8 -> _int))

(define SSLEAY_VERSION		0)
(define SSLEAY_CFLAGS		2)
(define SSLEAY_BUILT_ON		3)
(define SSLEAY_PLATFORM		4)
(define SSLEAY_DIR		5)

(define-crypto SSLeay_version (_fun _int -> _string/utf-8) #:fail (K (K #f)))
(define-crypto OpenSSL_version (_fun _int -> _string/utf-8) #:fail (K SSLeay_version))

(define (parse-version v)
  ;; MNNFFPPS
  (define S (bitwise-bit-field v 0 3))
  (define P (bitwise-bit-field v 4 11))
  (define F (bitwise-bit-field v 12 19))
  (define N (bitwise-bit-field v 20 27))
  (define M (bitwise-bit-field v 28 31))
  (values M N F P S))

(define (openssl-version>=? a b c)
  (define-values (va vb vc vd ve) (parse-version (OpenSSL_version_num)))
  (or (> va a)
      (and (= va a)
           (or (> vb b)
               (and (= vb b)
                    (>= vc c))))))

;; ============================================================
;; Bignum

(define-cpointer-type _BIGNUM)

(define-crypto BN_free
  (_fun _BIGNUM
        -> _void)
  #:wrap (deallocator))

(define BN-no-gc ((deallocator) void))

(define-crypto BN_new
  (_fun -> _BIGNUM/null)
  #:wrap (compose (allocator BN_free) (err-wrap/pointer 'BN_new)))

(define-crypto BN_add_word
  (_fun _BIGNUM
        _ulong
        -> _int)
  #:wrap (err-wrap 'BN_add_word))

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

;; New API since 1.1
(define-crypto EVP_MD_CTX_free (_fun _EVP_MD_CTX -> _void))
(define-crypto EVP_MD_CTX_new  (_fun -> _EVP_MD_CTX/null))

;; Old API through 1.0.2
(define-crypto EVP_MD_CTX_destroy (_fun _EVP_MD_CTX -> _void)
  #:fail (K EVP_MD_CTX_free)
  #:wrap (deallocator))
(define-crypto EVP_MD_CTX_create (_fun -> _EVP_MD_CTX/null)
  #:fail (K EVP_MD_CTX_new)
  #:wrap (compose (allocator EVP_MD_CTX_destroy) (err-wrap/pointer 'EVP_MD_CTX_create)))

(define-crypto EVP_Digest
  (_fun (inbuf inlen outbuf md) ::
        (inbuf : _pointer)
        (inlen : _size)
        (outbuf : _bytes)
        (outlen : (_ptr io _size) = (bytes-length outbuf))
        (md : _EVP_MD)
        (_pointer = #f)
        -> _int)
  #:wrap (err-wrap 'EVP_Digest))

(define-crypto EVP_DigestInit_ex
  (_fun _EVP_MD_CTX
        _EVP_MD
        (_pointer = #f)
        -> _int)
  #:wrap (err-wrap 'EVP_DigestInit_ex))

(define-crypto EVP_DigestUpdate
  (_fun _EVP_MD_CTX
        (d : _pointer)
        (cnt : _size)
        -> _int)
  #:wrap (err-wrap 'EVP_DigestUpdate))

(define-crypto EVP_DigestFinal_ex
  (_fun _EVP_MD_CTX
        (out : _pointer)
        (_pointer = #f)
        -> _int)
  #:wrap (err-wrap 'EVP_DigestFinal_ex))

(define-crypto EVP_MD_CTX_copy_ex
  (_fun _EVP_MD_CTX
        _EVP_MD_CTX
        -> _int)
  #:wrap (err-wrap 'EVP_MD_CTX_copy_ex))

(define-crypto HMAC
  (_fun _EVP_MD
        (key : _pointer)
        (keylen : _int)
        (d : _pointer)
        (n : _int)
        (md : _pointer)
        (len : (_ptr o _uint))
        -> (r : _pointer)
        -> (and r len))
  #:wrap (err-wrap 'HMAC values))

;; Old API, through 1.0.2
;;   malloc -> HMAC_CTX_init -> ...use... -> HMAC_CTX_cleanup -> free
(define-crypto HMAC_CTX_init  (_fun _HMAC_CTX -> _void))
(define-crypto HMAC_CTX_cleanup (_fun _HMAC_CTX -> _void))
(define (old-HMAC_CTX_free p)
  (begin (HMAC_CTX_cleanup p) (free p)))
(define (old-HMAC_CTX_new)
  (let ([hmac (malloc 'raw 300)]) ;; sizeof(HMAC_CTX) = 288 on linux-x86_64
    (cpointer-push-tag! hmac HMAC_CTX-tag)
    (HMAC_CTX_init hmac)
    hmac))

;; New API, since 1.1
;;   HMAC_CTX_new -> ...use... -> HMAC_CTX_free
(define-crypto HMAC_CTX_free (_fun _HMAC_CTX -> _void)
  #:fail (K old-HMAC_CTX_free)
  #:wrap (deallocator))
(define-crypto HMAC_CTX_new (_fun -> _HMAC_CTX/null)
  #:fail (K old-HMAC_CTX_new)
  #:wrap (compose (allocator HMAC_CTX_free) (err-wrap/pointer 'EVP_CTX_new)))
(define-crypto HMAC_CTX_reset (_fun _HMAC_CTX -> _int)
  #:wrap (err-wrap 'HMAC_CTX_reset))

(define-crypto HMAC_CTX_copy (_fun _HMAC_CTX _HMAC_CTX -> _int)
  #:wrap (err-wrap 'HMAC_CTX_copy))

(define-crypto HMAC_Init_ex
  (_fun _HMAC_CTX
        (key : _pointer)
        (keylen : _uint)
        _EVP_MD
        (_pointer = #f)
        -> _int) ;; _int since OpenSSL 1.0.0
  #:wrap (err-wrap 'HMAC_Init_ex))

(define-crypto HMAC_Update
  (_fun _HMAC_CTX
        (data : _pointer)
        (len : _uint)
        -> _int) ;; _int since OpenSSL 1.0.0
  #:wrap (err-wrap 'HMAC_Update))

(define-crypto HMAC_Final
  (_fun _HMAC_CTX
        (md : _pointer)
        (r : (_ptr o _int))
        -> (result : _int) ;; _int since OpenSSL 1.0.0
        -> (if (positive? result) r result))
  #:wrap (err-wrap 'HMAC_Final))

(define-crypto PKCS5_PBKDF2_HMAC
  (_fun (pass salt iter digest out) ::
        (pass    : _bytes)
        (plen    : _int = (bytes-length pass))
        (salt     : _bytes)
        (saltlen  : _int = (bytes-length salt))
        (iter     : _int)
        (digest   : _EVP_MD)
        (outlen   : _int = (bytes-length out))
        (out      : _bytes)
        -> _int)
  #:wrap (err-wrap 'PKCS5_PBKDF2_HMAC))

(define-crypto EVP_PBE_scrypt
  (_fun (pass salt N r p maxmem out) ::
        (pass : _bytes) (passlen : _size = (bytes-length pass))
        (salt : _bytes) (saltlen : _size = (bytes-length salt))
        (N : _uint64)
        (r : _uint64)
        (p : _uint64)
        (maxmem : _uint64)
        (out : _bytes)  (outlen : _size = (bytes-length out))
        -> _int)
  #:wrap (err-wrap 'EVP_PBE_scrypt))

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
  #:wrap (err-wrap 'EVP_CIPHER_CTX_cleanup))

(define-crypto EVP_CipherInit_ex
  (_fun _EVP_CIPHER_CTX
        _EVP_CIPHER
        (_pointer = #f)
        (key : _pointer)
        (iv : _pointer)
        (enc? : _bool)
        -> _int)
  #:wrap (err-wrap 'EVP_CipherInit_ex))

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

;; Returns 0 on AE decryption auth-failure, but no ERR_get_error.
;; FIXME: Assuming if no error, means auth failure.
(define-crypto EVP_CipherFinal_ex
  (_fun (ctx out) ::
        (ctx : _EVP_CIPHER_CTX)
        (out : _pointer)
        (olen : (_ptr o _int))
        -> (result : _int)
        -> (cond [(= result 1) olen]
                 [(positive? (ERR_peek_error))
                  (raise-crypto-error 'EVP_CipherFinal_ex)]
                 [else #f])))

(define-crypto EVP_CIPHER_CTX_set_key_length
  (_fun _EVP_CIPHER_CTX _int -> _int)
  #:wrap (err-wrap 'EVP_CIPHER_CTX_set_key_length))

(define-crypto EVP_CIPHER_CTX_ctrl
  (_fun _EVP_CIPHER_CTX _int _int _pointer -> _int)
  #:wrap (err-wrap 'EVP_CIPHER_CTX_ctrl))

(define-crypto EVP_CIPHER_CTX_set_padding
  (_fun _EVP_CIPHER_CTX _bool -> _int)
  #:wrap (err-wrap 'EVP_CIPHER_CTX_set_padding))

(define         EVP_CTRL_AEAD_SET_IVLEN         #x9)
(define         EVP_CTRL_AEAD_GET_TAG           #x10)
(define         EVP_CTRL_AEAD_SET_TAG           #x11)
(define         EVP_CTRL_AEAD_SET_IV_FIXED      #x12)
(define         EVP_CTRL_GCM_IV_GEN             #x13)
(define         EVP_CTRL_CCM_SET_L              #x14)
(define         EVP_CTRL_CCM_SET_MSGLEN         #x15)

(define-crypto EVP_CIPHER_block_size (_fun _EVP_CIPHER -> _int))
(define-crypto EVP_CIPHER_key_length (_fun _EVP_CIPHER -> _int))
(define-crypto EVP_CIPHER_iv_length  (_fun _EVP_CIPHER -> _int))

;; ============================================================
;; Diffie-Hellman

(define-cstruct _DH_st_prefix
  ([pad     _int]
   [version _int]
   [p       _BIGNUM]
   [g       _BIGNUM]
   [length  _long]
   [pubkey  _BIGNUM/null]
   [privkey _BIGNUM/null]
   ;; more fields
   ))

(define _DH _DH_st_prefix-pointer)
(define _DH/null _DH_st_prefix-pointer/null)

(define-crypto DH_free
  (_fun _DH -> _void)
  #:wrap (deallocator))

(define-crypto DH_new
  (_fun -> _DH/null)
  #:wrap (compose (allocator DH_free) (err-wrap/pointer 'DH_new)))

(define-crypto DHparams_dup
  (_fun _DH -> _DH))

(define-crypto DH_size
  (_fun _DH -> _int))

(define-crypto DH_generate_parameters_ex
  (_fun _DH _int _int (_fpointer = #f) -> _int)
  #:wrap (err-wrap 'DH_generate_parameters_ex))

;; PKCS#3 DH params
(define-crypto i2d_DHparams
  (_fun _DH (_ptr i _pointer) -> _int)
  #:wrap (err-wrap 'i2d_DHparams))
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
  #:wrap (err-wrap 'DH_generate_key))

(define-crypto DH_compute_key
  (_fun (dh pub) ::
        (secret : _pointer = (make-bytes (DH_size dh)))
        (pub : _BIGNUM)
        (dh : _DH)
        -> (status : _int)
        -> (and (positive? status) secret))
  #:wrap (err-wrap 'DH_compute_key values))

;; ============================================================
;; RSA, DSA

(define-cpointer-type _RSA)
(define-cpointer-type _DSA)

(define-crypto RSA_free
  (_fun _RSA -> _void)
  #:wrap (deallocator))

(define-crypto RSA_new
  (_fun -> _RSA/null)
  #:wrap (compose (allocator RSA_free) (err-wrap/pointer 'RSA_new)))

(define-crypto RSA_generate_key_ex
  (_fun _RSA _int _BIGNUM/null _fpointer -> _int)
  #:wrap (err-wrap 'RSA_generate_key_ex))

(define-crypto DSA_free
  (_fun _DSA -> _void)
  #:wrap (deallocator))

(define-crypto DSA_new
  (_fun -> _DSA/null)
  #:wrap (compose (allocator DSA_free) (err-wrap/pointer 'DSA_new)))

(define-crypto DSA_generate_parameters_ex
  (_fun _DSA _int (_pointer = #f) (_int = 0) (_pointer = #f) (_pointer = #f) (_pointer = #f)
        -> _int)
  #:wrap (err-wrap 'DSA_generate_parameters_ex))

(define-crypto DSA_generate_key
  (_fun _DSA -> _int)
  #:wrap (err-wrap 'DSA_generate_key))

;; ============================================================
;; EC

(define-cpointer-type _EC_KEY)
(define-cpointer-type _EC_GROUP)
(define-cpointer-type _EC_POINT)

(define-crypto EC_GROUP_free
  (_fun _EC_GROUP -> _void)
  #:wrap (deallocator))

(define-crypto EC_GROUP_dup
  (_fun _EC_GROUP -> _EC_GROUP))

(define-crypto EC_GROUP_get_degree
  (_fun _EC_GROUP -> _int)
  #:wrap (err-wrap 'EC_GROUP_get_degree))

(define-crypto EC_GROUP_new_by_curve_name
  (_fun _int -> _EC_GROUP/null)
  #:wrap (err-wrap/pointer 'EC_GROUP_new_by_curve_name))

(define-crypto i2d_ECPKParameters
  (_fun _EC_GROUP (_ptr i _pointer) -> _int)
  #:wrap (err-wrap 'i2d_ECPKParameters))

(define-crypto d2i_ECPKParameters
  (_fun (_pointer = #f) (_ptr i _pointer) _long
        -> _EC_GROUP)
  #:wrap (err-wrap/pointer 'd2i_ECPKParameters))

(define-crypto EC_KEY_free
  (_fun _EC_KEY -> _void)
  #:wrap (deallocator))

(define-crypto EC_KEY_new
  (_fun -> _EC_KEY/null)
  #:wrap (compose (allocator EC_KEY_free) (err-wrap/pointer 'EC_KEY_new)))

(define-crypto EC_KEY_dup
  (_fun _EC_KEY -> _EC_KEY))

(define-crypto EC_KEY_new_by_curve_name
  (_fun _int -> _EC_KEY/null)
  #:wrap (compose (allocator EC_KEY_free) (err-wrap/pointer 'EC_KEY_new_by_curve_name)))

(define-crypto EC_KEY_set_group
  (_fun _EC_KEY _EC_GROUP -> _int)
  #:wrap (err-wrap 'EC_KEY_set_group))

(define-crypto EC_KEY_get0_group
  (_fun _EC_KEY -> _EC_GROUP/null)
  #:wrap (err-wrap/pointer 'EC_KEY_get0_group))

(define-crypto EC_KEY_generate_key
  (_fun _EC_KEY -> _int)
  #:wrap (err-wrap 'EC_KEY_generate_key))

(define-crypto ECDH_compute_key
  (_fun _pointer _size _EC_POINT _EC_KEY (_fpointer = #f)
        -> _int)
  #:wrap (err-wrap 'ECDH_compute_key))

(define-crypto EC_POINT_free
  (_fun _EC_POINT -> _void)
  #:wrap (deallocator))

(define-crypto EC_POINT_new
  (_fun _EC_GROUP -> _EC_POINT/null)
  #:wrap (compose (allocator EC_POINT_free) (err-wrap/pointer 'EC_POINT_new)))

(define-crypto EC_POINT_oct2point
  (_fun _EC_GROUP _EC_POINT _pointer _size (_pointer = #f)
        -> _int)
  #:wrap (err-wrap 'EC_POINT_oct2point))

(define _point_conversion_form _int)
(define POINT_CONVERSION_COMPRESSED 2)
(define POINT_CONVERSION_UNCOMPRESSED 4)
(define POINT_CONVERSION_HYBRID 6)

(define-crypto EC_POINT_point2oct
  (_fun _EC_GROUP _EC_POINT _point_conversion_form _pointer _size (_pointer = #f)
        -> _size)
  #:wrap (err-wrap 'EC_POINT_point2oct))

(define-crypto EC_KEY_get0_public_key
  (_fun _EC_KEY -> _EC_POINT/null)
  #:wrap (err-wrap/pointer 'EC_KEY_get0_public_key))

(define-crypto EC_KEY_set_public_key
  (_fun _EC_KEY _EC_POINT -> _int)
  #:wrap (err-wrap 'EC_KEY_set_public_key))

(define-crypto EC_KEY_get0_private_key
  (_fun _EC_KEY -> _BIGNUM/null)
  #:wrap (err-wrap/pointer 'EC_KEY_get0_private_key))

(define-crypto EC_KEY_set_private_key
  (_fun _EC_KEY _BIGNUM -> _int)
  #:wrap (err-wrap 'EC_KEY_set_private_key))

(define-cstruct _EC_builtin_curve
  ([nid     _int]
   [comment _string/utf-8]))

(define-crypto EC_get_builtin_curves
  (_fun _EC_builtin_curve-pointer/null _size -> _size))

;; ============================================================
;; EVP_PKEY

(define-cpointer-type _EVP_PKEY)
(define-cpointer-type _EVP_PKEY_CTX)

(define EVP_PKEY_RSA    6)
(define EVP_PKEY_DSA    116)
(define EVP_PKEY_DH     28)
(define EVP_PKEY_EC     408)
(define NID_X25519      1034)
(define NID_X448        1035)
(define NID_ED25519     1087)
(define NID_ED448       1088)

(define type=>spec
  `((,EVP_PKEY_RSA . rsa)
    (,EVP_PKEY_DSA . dsa)
    (,EVP_PKEY_DH  . dh)
    (,EVP_PKEY_EC  . ec)
    (,NID_ED25519  . eddsa)
    (,NID_ED448    . eddsa)
    (,NID_X25519   . ecx)
    (,NID_X448     . ecx)))

(define-crypto EVP_PKEY_free
  (_fun _EVP_PKEY -> _void)
  #:wrap (deallocator))

(define-crypto EVP_PKEY_new
  (_fun -> _EVP_PKEY/null)
  #:wrap (compose (allocator EVP_PKEY_free) (err-wrap/pointer 'EVP_PKEY_new)))

(define (EVP->type evp)
  ;; Don't bother defining whole cstruct, since type is first field (ie, offset 0)
  (EVP_PKEY_type (ptr-ref evp _int)))

(define-crypto EVP_PKEY_CTX_free
  (_fun _EVP_PKEY_CTX -> _void)
  #:wrap (deallocator))

(define-crypto EVP_PKEY_CTX_new
  (_fun _EVP_PKEY (_pointer = #f) -> _EVP_PKEY_CTX)
  #:wrap (compose (allocator EVP_PKEY_CTX_free) (err-wrap/pointer 'EVP_PKEY_CTX_new)))

(define-crypto EVP_PKEY_CTX_new_id
  (_fun _int (_pointer = #f) -> _EVP_PKEY_CTX)
  #:wrap (compose (allocator EVP_PKEY_CTX_free) (err-wrap/pointer 'EVP_PKEY_CTX_new_id)))

(define-crypto EVP_PKEY_CTX_set_cb
  (_fun _EVP_PKEY_CTX _fpointer -> _void))

(define-crypto EVP_PKEY_keygen_init
  (_fun _EVP_PKEY_CTX -> _int)
  #:wrap (err-wrap 'EVP_PKEY_keygen_init))

(define-crypto EVP_PKEY_paramgen_init
  (_fun _EVP_PKEY_CTX -> _int)
  #:wrap (err-wrap 'EVP_PKEY_paramgen_init))

(define-crypto EVP_PKEY_CTX_ctrl
  (_fun _EVP_PKEY_CTX
        (keytype : _int)
        (optype : _int)
        (cmd : _int)
        (p1 : _int)
        (p2 : _pointer)
        -> _int)
  #:wrap (err-wrap 'EVP_PKEY_CTX_ctrl))

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
  #:wrap (err-wrap 'EVP_PKEY_copy_parameters))

(define-crypto EVP_PKEY_cmp_parameters
  (_fun _EVP_PKEY _EVP_PKEY -> _int)
  #:wrap (err-wrap 'EVP_PKEY_cmp_parameters
                   (lambda (r) (member r '(0 1)))
                   #:convert (lambda (r) (case r ((0) #f) ((1) #t)))))

(define-crypto EVP_PKEY_type
  (_fun _int -> _int)
  #:wrap (err-wrap 'EVP_PKEY_type))

(define-crypto EVP_PKEY_set_type
  (_fun _EVP_PKEY _int -> _int)
  #:wrap (err-wrap 'EVP_PKEY_set_type))

(define-crypto EVP_PKEY_size
  (_fun _EVP_PKEY -> _int)
  #:wrap (err-wrap 'EVP_PKEY_size))

(define-crypto EVP_PKEY_bits
  (_fun _EVP_PKEY -> _int)
  #:wrap (err-wrap 'EVP_PKEY_bits))

(define-crypto EVP_PKEY_set1_RSA
  (_fun _EVP_PKEY _RSA -> _int)
  #:wrap (err-wrap 'EVP_PKEY_set1_RSA))

(define-crypto EVP_PKEY_set1_DSA
  (_fun _EVP_PKEY _DSA -> _int)
  #:wrap (err-wrap 'EVP_PKEY_set1_DSA))

(define-crypto EVP_PKEY_set1_DH
  (_fun _EVP_PKEY _DH -> _int)
  #:wrap (err-wrap 'EVP_PKEY_set1_DH))

(define-crypto EVP_PKEY_set1_EC_KEY
  (_fun _EVP_PKEY _EC_KEY -> _int)
  #:wrap (err-wrap 'EVP_PKEY_set1_EC))

(define-crypto EVP_PKEY_get1_RSA
  (_fun _EVP_PKEY -> _RSA/null)
  #:wrap (compose (allocator RSA_free) (err-wrap/pointer 'EVP_PKEY_get1_RSA)))

(define-crypto EVP_PKEY_get1_DSA
  (_fun _EVP_PKEY -> _DSA/null)
  #:wrap (compose (allocator DSA_free) (err-wrap/pointer 'EVP_PKEY_get1_DSA)))

(define-crypto EVP_PKEY_get1_DH
  (_fun _EVP_PKEY -> _DH/null)
  #:wrap (compose (allocator DH_free) (err-wrap/pointer 'EVP_PKEY_get1_DH)))

(define-crypto EVP_PKEY_get1_EC_KEY
  (_fun _EVP_PKEY -> _EC_KEY/null)
  #:wrap (compose (allocator EC_KEY_free) (err-wrap/pointer 'EVP_PKEY_get1_EC_KEY)))

(define-crypto EVP_PKEY_sign_init
  (_fun _EVP_PKEY_CTX -> _int)
  #:wrap (err-wrap 'EVP_PKEY_sign_init))

(define-crypto EVP_PKEY_sign
  (_fun _EVP_PKEY_CTX _pointer (siglen : (_ptr io _size)) _pointer _size
        -> (status : _int)
        -> (if (positive? status) siglen status))
  #:wrap (err-wrap 'EVP_PKEY_sign))

(define-crypto EVP_PKEY_verify_init
  (_fun _EVP_PKEY_CTX -> _int)
  #:wrap (err-wrap 'EVP_PKEY_verify_init))

(define-crypto EVP_PKEY_verify
  (_fun _EVP_PKEY_CTX _pointer _size _pointer _size -> _int)
  #:wrap (err-wrap 'EVP_PKEY_verify
                   (lambda (r) (member r '(0 1)))
                   #:convert (lambda (r) (case r ((0) #f) ((1) #t)))
                   #:drain? #t))

(define-crypto EVP_PKEY_encrypt_init
  (_fun _EVP_PKEY_CTX -> _int)
  #:wrap (err-wrap 'EVP_PKEY_encrypt_init))

(define-crypto EVP_PKEY_encrypt
  (_fun _EVP_PKEY_CTX _pointer (outlen : (_ptr io _size)) _pointer _size
        -> (status : _int)
        -> (if (positive? status) outlen status))
  #:wrap (err-wrap 'EVP_PKEY_encrypt))

(define-crypto EVP_PKEY_decrypt_init
  (_fun _EVP_PKEY_CTX -> _int)
  #:wrap (err-wrap 'EVP_PKEY_decrypt_init))

(define-crypto EVP_PKEY_decrypt
  (_fun _EVP_PKEY_CTX _pointer (outlen : (_ptr io _size)) _pointer _size
        -> (status : _int)
        -> (if (positive? status) outlen status))
  #:wrap (err-wrap 'EVP_PKEY_decrypt))

(define-crypto EVP_PKEY_derive_init
  (_fun _EVP_PKEY_CTX -> _int)
  #:wrap (err-wrap 'EVP_PKEY_derive_init))

(define-crypto EVP_PKEY_derive_set_peer
  (_fun _EVP_PKEY_CTX _EVP_PKEY -> _int)
  #:wrap (err-wrap 'EVP_PKEY_derive_set_peer))

(define-crypto EVP_PKEY_derive
  (_fun _EVP_PKEY_CTX _pointer (outlen : (_ptr io _size))
        -> (status : _int)
        -> (if (positive? status) outlen status))
  #:wrap (err-wrap 'EVP_PKEY_derive))

(define-crypto EVP_PKEY_cmp
  (_fun _EVP_PKEY _EVP_PKEY -> _int)
  #:wrap (err-wrap 'EVP_PKEY_cmp
                   (lambda (r) (member r '(0 1)))
                   #:convert (lambda (r) (case r ((0) #f) ((1) #t)))))

;; EVP_PKEY_*_check since v1.1.1
(define-crypto EVP_PKEY_check (_fun _EVP_PKEY_CTX -> _int)
  #:wrap (err-wrap 'EVP_PKEY_check) #:fail (K (K 1)))
(define-crypto EVP_PKEY_public_check (_fun _EVP_PKEY_CTX -> _int)
  #:wrap (err-wrap 'EVP_PKEY_public_check) #:fail (K (K 1)))
(define-crypto EVP_PKEY_param_check (_fun _EVP_PKEY_CTX -> _int)
  #:wrap (err-wrap 'EVP_PKEY_param_check) #:fail (K (K 1)))

(define-crypto d2i_PublicKey
  (_fun _int (_pointer = #f) (_ptr i _pointer) _long -> _EVP_PKEY/null)
  #:wrap (compose (allocator EVP_PKEY_free) (err-wrap/pointer 'd2i_PublicKey)))

(define-crypto d2i_PrivateKey
  (_fun _int (_pointer = #f) (_ptr i _pointer) _long -> _EVP_PKEY/null)
  #:wrap (compose (allocator EVP_PKEY_free) (err-wrap/pointer 'd2i_PrivateKey)))

(define-crypto i2d_PublicKey
  (_fun _EVP_PKEY (_ptr i _pointer) -> _int)
  #:wrap (err-wrap 'i2d_PublicKey))

(define-crypto i2d_PrivateKey
  (_fun _EVP_PKEY (_ptr i _pointer) -> _int)
  #:wrap (err-wrap 'i2d_PrivateKey))

(define-crypto d2i_PUBKEY
  (_fun (_pointer = #f) (_ptr i _pointer) _long -> _EVP_PKEY/null)
  #:wrap (compose (allocator EVP_PKEY_free) (err-wrap/pointer 'd2i_PUBKEY)))
(define-crypto i2d_PUBKEY
  (_fun _EVP_PKEY (_ptr i _pointer) -> _int)
  #:wrap (err-wrap 'i2d_PUBKEY))

(define-cpointer-type _PKCS8_PRIV_KEY_INFO)
(define-crypto PKCS8_PRIV_KEY_INFO_free
  (_fun _PKCS8_PRIV_KEY_INFO -> _void))

(define-crypto EVP_PKCS82PKEY
  (_fun _PKCS8_PRIV_KEY_INFO -> _EVP_PKEY/null)
  #:wrap (compose (allocator EVP_PKEY_free) (err-wrap/pointer 'EVP_PKCS82PKEY)))
(define-crypto EVP_PKEY2PKCS8
  (_fun _EVP_PKEY -> _PKCS8_PRIV_KEY_INFO/null)
  #:wrap (compose (allocator PKCS8_PRIV_KEY_INFO_free) (err-wrap/pointer 'EVP_PKEY2PKCS8)))

(define-crypto d2i_PKCS8_PRIV_KEY_INFO
  (_fun (_pointer = #f) (_ptr i _pointer) _long -> _PKCS8_PRIV_KEY_INFO/null)
  #:wrap (compose (allocator PKCS8_PRIV_KEY_INFO_free)
                  (err-wrap/pointer 'd2i_PKCS8_PRIV_KEY_INFO)))
(define-crypto i2d_PKCS8_PRIV_KEY_INFO
  (_fun _PKCS8_PRIV_KEY_INFO (_ptr i _pointer) -> _int)
  #:wrap (err-wrap 'i2d_PKCS8_PRIV_KEY_INFO))

(define-crypto d2i_DSAparams
  (_fun (_pointer = #f) (_ptr i _pointer) _long -> _DSA/null)
  #:wrap (compose (allocator DSA_free) (err-wrap/pointer 'd2i_DSAparams)))

(define-crypto i2d_DSAparams
  (_fun _DSA (_ptr i _pointer) -> _int)
  #:wrap (err-wrap 'i2d_DSAparams))

(define-crypto d2i_ECPrivateKey
  (_fun (_pointer = #f) (_ptr i _pointer) _long -> _EC_KEY/null)
  #:wrap (compose (allocator EC_KEY_free) (err-wrap/pointer 'd2i_ECPrivateKey)))

(define-crypto i2d_ECPrivateKey
  (_fun _EC_KEY (_ptr i _pointer) -> _int)
  #:wrap (err-wrap 'i2d_ECPrivateKey))

(define-crypto o2i_ECPublicKey
  (_fun (_pointer = #f) (_ptr i _pointer) _long -> _EC_KEY/null)
  #:wrap (compose (allocator EC_KEY_free) (err-wrap/pointer 'o2i_ECPublicKey)))

(define-crypto i2o_ECPublicKey
  (_fun _EC_KEY (_ptr i _pointer) -> _int)
  #:wrap (err-wrap 'i2o_ECPublicKey))

(define OPENSSL_EC_NAMED_CURVE 1)

(define-crypto EC_KEY_set_asn1_flag
  (_fun _EC_KEY _int -> _void))

;; ============================================================
;; New PKEY

(define-crypto EVP_PKEY_new_raw_private_key
  (_fun (type : _int) (_pointer = #f) (key : _pointer) (klen : _size) -> _EVP_PKEY)
  #:wrap (compose (allocator EVP_PKEY_free)
                  (err-wrap/pointer 'EVP_PKEY_new_raw_private_key)))

(define-crypto EVP_PKEY_new_raw_public_key
  (_fun (type : _int) (_pointer = #f) (key : _pointer) (klen : _size) -> _EVP_PKEY)
  #:wrap (compose (allocator EVP_PKEY_free)
                  (err-wrap/pointer 'EVP_PKEY_new_raw_public_key)))

;; (define-crypto EVP_PKEY_get_raw_private_key
;;   (_fun (pkey : _EVP_PKEY) (priv : _pointer) (len : (_ptr io _size)) -> _int)
;;   #:wrap (err-wrap 'EVP_PKEY_get_raw_private_key))
;; (define-crypto EVP_PKEY_get_raw_public_key
;;   (_fun (pkey : _EVP_PKEY) (pub : _pointer) (len : (_ptr io _size)) -> _int)
;;   #:wrap (err-wrap 'EVP_PKEY_get_raw_public_key))

(define-crypto EVP_DigestSignInit
  (_fun (ctx : _EVP_MD_CTX) (_pointer = #f) (md : _EVP_MD/null) (_pointer = #f) (k : _EVP_PKEY)
        -> _int)
  #:wrap (err-wrap 'EVP_DigestSignInit))

(define-crypto EVP_DigestSign
  (_fun (ctx : _EVP_MD_CTX) (sig : _pointer) (siglen : (_ptr io _size))
        (msg : _pointer) (mlen : _size)
        -> _int)
  #:wrap (err-wrap 'EVP_DigestSign))

(define-crypto EVP_DigestVerifyInit
  (_fun (ctx : _EVP_MD_CTX) (_pointer = #f) (md : _EVP_MD/null) (_pointer = #f) (k : _EVP_PKEY)
        -> _int)
  #:wrap (err-wrap 'EVP_DigestVerifyInit))

(define-crypto EVP_DigestVerify
  (_fun (ctx : _EVP_MD_CTX) (sig : _pointer) (siglen : _size)
        (msg : _pointer) (mlen : _size)
        -> (s : _int) -> (> s 0)))

;; ============================================================
;; Random Numbers

(define-crypto RAND_bytes
  (_fun _pointer _int -> _int)
  #:wrap (err-wrap 'RAND_bytes))

(define-crypto RAND_status
  (_fun -> _int))

(define-crypto RAND_add
  (_fun _pointer _int _double -> _void))

(define-crypto RAND_load_file
  (_fun _path _long -> _int))

(define-crypto RAND_write_file
  (_fun _path -> _int))
