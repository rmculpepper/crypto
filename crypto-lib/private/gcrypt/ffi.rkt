;; Copyright 2012-2018 Ryan Culpepper
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

(require (for-syntax racket/base)
         ffi/unsafe
         ffi/unsafe/alloc
         ffi/unsafe/atomic
         ffi/unsafe/define
         racket/runtime-path
         "../common/error.rkt"
         "../common/ffi.rkt")

(provide (protect-out (all-defined-out)))

;; Cooperate with `raco distribute`.
(define-runtime-path libgcrypt-so
  '(so "libgcrypt" ("20" #f)))

;; depended on by libgcrypt
(define-runtime-path libgpg-error-so
  '(so "libgpg-error"))

(define-values (libgcrypt gcrypt-load-error)
  (ffi-lib-or-why-not libgcrypt-so '("20" #f)))

(define-ffi-definer define-gcrypt libgcrypt
  #:default-make-fail make-not-available)

(define gcrypt-ok? (and libgcrypt #t))

;; ----

(define _gcry_error _uint)

(define (gcry_error-code e)
  ;; From gpg-error.h: the lower 16 bits are used to store error codes;
  ;; higher bits store other information (eg error source).
  (bitwise-and e #xFFFF))

(define GPG_ERR_NO_ERROR 0)
(define GPG_ERR_BAD_SIGNATURE 8)

(define-gcrypt gcry_strerror (_fun _gcry_error -> _string))

(define ((check f) . args)
  (call-as-atomic
   (lambda ()
     (let ([status (apply f args)])
       (if (= status GPG_ERR_NO_ERROR)
           (void)
           (crypto-error "libgcrypt error: ~a" (gcry_strerror status)))))))

(define ((check2 f) . args)
  (call-as-atomic
   (lambda ()
     (let-values ([(status result) (apply f args)])
       (if (= status GPG_ERR_NO_ERROR)
           result
           (crypto-error "libgcrypt error: ~a" (gcry_strerror status)))))))

(define-gcrypt gcry_check_version
  (_fun _bytes -> _string/utf-8)
  #:fail (lambda () (lambda _ #f)))

(define GCRYCTL_ENABLE_QUICK_RANDOM 44)
(define-gcrypt gcry_control
  (_fun _int _int -> _gcry_error)
  #:wrap check)

;; Library Initialization

;; (void (gcry_control GCRYCTL_ENABLE_QUICK_RANDOM 0))
(void (gcry_check_version #f))

;; ----

(define-cpointer-type _gcry_md_hd)

(define GCRY_MD_NONE           0)
(define GCRY_MD_MD5            1)
(define GCRY_MD_SHA1           2)
(define GCRY_MD_RMD160         3)
(define GCRY_MD_MD2            5)
(define GCRY_MD_TIGER          6) ;; TIGER/192 as used by GnuPG < 1.3.2.
(define GCRY_MD_HAVAL          7) ;; HAVAL 5 pass 160 bit.
(define GCRY_MD_SHA256         8)
(define GCRY_MD_SHA384         9)
(define GCRY_MD_SHA512         10)
(define GCRY_MD_SHA224         11)
(define GCRY_MD_MD4            301)
(define GCRY_MD_CRC32          302)
(define GCRY_MD_CRC32_RFC1510  303)
(define GCRY_MD_CRC24_RFC2440  304)
(define GCRY_MD_WHIRLPOOL      305)
(define GCRY_MD_TIGER1         306) ;; TIGER (fixed).
(define GCRY_MD_TIGER2         307) ;; TIGER2 variant.
(define GCRY_MD_SHA3_224       312)
(define GCRY_MD_SHA3_256       313)
(define GCRY_MD_SHA3_384       314)
(define GCRY_MD_SHA3_512       315)
(define GCRY_MD_SHAKE128       316)
(define GCRY_MD_SHAKE256       317)
(define GCRY_MD_BLAKE2B_512    318)
(define GCRY_MD_BLAKE2B_384    319)
(define GCRY_MD_BLAKE2B_256    320)
(define GCRY_MD_BLAKE2B_160    321)
(define GCRY_MD_BLAKE2S_256    322)
(define GCRY_MD_BLAKE2S_224    323)
(define GCRY_MD_BLAKE2S_160    324)
(define GCRY_MD_BLAKE2S_128    325)

(define GCRY_MD_FLAG_SECURE    1) ;; Allocate all buffers in "secure" memory.
(define GCRY_MD_FLAG_HMAC      2) ;; Make an HMAC out of this algorithm.

(define GCRYCTL_TEST_ALGO      8)
(define GCRYCTL_FINALIZE       5)

(define-gcrypt gcry_md_close
  (_fun _gcry_md_hd -> _void)
  #:wrap (deallocator))

(define-gcrypt gcry_md_open
  (_fun (ctx : (_ptr o _gcry_md_hd/null))
        _int
        _uint
        -> (status : _gcry_error)
        -> (values status ctx))
  #:wrap (compose (allocator gcry_md_close) check2))

(define-gcrypt gcry_md_enable
  (_fun _gcry_md_hd _int -> _gcry_error)
  #:wrap check)

(define-gcrypt gcry_md_setkey
  (_fun _gcry_md_hd _pointer _size -> _gcry_error)
  #:wrap check)

(define-gcrypt gcry_md_reset (_fun _gcry_md_hd -> _void))

(define-gcrypt gcry_md_copy
  (_fun (ctx2 : (_ptr o _gcry_md_hd/null))
        _gcry_md_hd
        -> (status : _gcry_error)
        -> (values status ctx2))
  #:wrap (compose (allocator gcry_md_close) check2))

(define-gcrypt gcry_md_write (_fun _gcry_md_hd _pointer _size -> _void))

(define-gcrypt gcry_md_read
  (_fun (handle buf len) :: (handle : _gcry_md_hd) (_int = 0)
        -> (result : _pointer)
        -> (memmove buf result len)))

(define-gcrypt gcry_md_hash_buffer (_fun _int _pointer _pointer _size -> _void))
(define-gcrypt gcry_md_algo_name (_fun _int -> _string))
(define-gcrypt gcry_md_map_name (_fun _string -> _int))
(define-gcrypt gcry_md_get_algo_dlen (_fun _int -> _uint))

(define-gcrypt gcry_md_algo_info
  ;; no #:wrap check because result sometimes encodes boolean (inverted)
  (_fun _int _int _pointer _pointer -> _gcry_error))

(define (gcry_md_test_algo a)
  (if gcrypt-ok?
      (zero? (gcry_md_algo_info a GCRYCTL_TEST_ALGO #f #f))
      #f))

(define GCRY_KDF_PBKDF2 34) ;; really PBKDF2-HMAC-<digest>
(define GCRY_KDF_SCRYPT 48) ;; since v1.6

(define-gcrypt gcry_kdf_derive
  (_fun (input algo subalgo salt iters outlen) ::
        (input   : _bytes)
        (inlen   : _size = (bytes-length input))
        (algo    : _int)
        (subalgo : _int)
        (salt    : _bytes)
        (saltlen : _size = (bytes-length salt))
        (iters   : _ulong)
        (outlen  : _size)
        (out     : (_bytes o outlen))
        -> (status : _gcry_error)
        -> (values status out))
  #:wrap check2)

;; ----

(define-cpointer-type _gcry_cipher_hd)

(define GCRY_CIPHER_NONE         0)
(define GCRY_CIPHER_IDEA         1)
(define GCRY_CIPHER_3DES         2)
(define GCRY_CIPHER_CAST5        3)
(define GCRY_CIPHER_BLOWFISH     4)
(define GCRY_CIPHER_SAFER_SK128  5)
(define GCRY_CIPHER_DES_SK       6)
(define GCRY_CIPHER_AES          7)
(define GCRY_CIPHER_AES192       8)
(define GCRY_CIPHER_AES256       9)
(define GCRY_CIPHER_TWOFISH      10)

;; Other cipher numbers are above 300 for OpenPGP reasons.
(define GCRY_CIPHER_ARCFOUR      301) ;; Fully compatible with RSA's RC4 (tm).
(define GCRY_CIPHER_DES          302) ;; Yes this is single key 56 bit DES.
(define GCRY_CIPHER_TWOFISH128   303)
(define GCRY_CIPHER_SERPENT128   304)
(define GCRY_CIPHER_SERPENT192   305)
(define GCRY_CIPHER_SERPENT256   306)
(define GCRY_CIPHER_RFC2268_40   307) ;; Ron's Cipher 2 (40 bit).
(define GCRY_CIPHER_RFC2268_128  308) ;; Ron's Cipher 2 (128 bit).
(define GCRY_CIPHER_SEED         309) ;; 128 bit cipher described in RFC4269.
(define GCRY_CIPHER_CAMELLIA128  310)
(define GCRY_CIPHER_CAMELLIA192  311)
(define GCRY_CIPHER_CAMELLIA256  312)
(define GCRY_CIPHER_SALSA20      313)
(define GCRY_CIPHER_SALSA20R12   314) ;; added v1.6.0
(define GCRY_CIPHER_CHACHA20     316) ;; added ??

(define GCRY_CIPHER_MODE_NONE    0) ;; Not yet specified.
(define GCRY_CIPHER_MODE_ECB     1) ;; Electronic codebook.
(define GCRY_CIPHER_MODE_CFB     2) ;; Cipher feedback.
(define GCRY_CIPHER_MODE_CBC     3) ;; Cipher block chaining.
(define GCRY_CIPHER_MODE_STREAM  4) ;; Used with stream ciphers.
(define GCRY_CIPHER_MODE_OFB     5) ;; Outer feedback.
(define GCRY_CIPHER_MODE_CTR     6) ;; Counter.
(define GCRY_CIPHER_MODE_AESWRAP 7) ;; AES-WRAP algorithm.
(define GCRY_CIPHER_MODE_CCM     8)
(define GCRY_CIPHER_MODE_GCM     9) ;; introduced v1.6.0
(define GCRY_CIPHER_MODE_POLY1305 10) ;; introduced ???
(define GCRY_CIPHER_MODE_OCB     11)
(define GCRY_CIPHER_MODE_CFB8    12)
(define GCRY_CIPHER_MODE_XTS     13)

(define-gcrypt gcry_cipher_close
  (_fun _gcry_cipher_hd -> _void)
  #:wrap (deallocator))

(define-gcrypt gcry_cipher_open
  (_fun (ctx : (_ptr o _gcry_cipher_hd/null)) _int _int _uint
        -> (result : _gcry_error)
        -> (values result ctx))
  #:wrap (compose (allocator gcry_cipher_close) check2))

(define-gcrypt gcry_cipher_setkey
  (_fun _gcry_cipher_hd _pointer _size -> _gcry_error)
  #:wrap check)

(define-gcrypt gcry_cipher_setiv
  (_fun _gcry_cipher_hd _pointer _size -> _gcry_error)
  #:wrap check)

(define-gcrypt gcry_cipher_setctr
  (_fun _gcry_cipher_hd _pointer _size -> _gcry_error)
  #:wrap check)

(define-gcrypt gcry_cipher_authenticate
  (_fun _gcry_cipher_hd _pointer _size -> _gcry_error)
  #:wrap check)

(define-gcrypt gcry_cipher_gettag
  (_fun _gcry_cipher_hd _pointer _size -> _gcry_error)
  #:wrap check)

(define-gcrypt gcry_cipher_checktag
  (_fun _gcry_cipher_hd _pointer _size -> _gcry_error))

(define-gcrypt gcry_cipher_encrypt
  (_fun _gcry_cipher_hd _pointer _size _pointer _size -> _gcry_error)
  #:wrap check)

(define-gcrypt gcry_cipher_decrypt
  (_fun _gcry_cipher_hd _pointer _size _pointer _size -> _gcry_error)
  #:wrap check)

(define-gcrypt gcry_cipher_get_algo_keylen (_fun _int -> _size))
(define-gcrypt gcry_cipher_get_algo_blklen (_fun _int -> _size))

(define-gcrypt gcry_cipher_algo_info
  ;; no #:wrap check because result sometimes encodes boolean (inverted)
  (_fun _int _int _pointer _pointer -> _gcry_error))

(define (gcry_cipher_test_algo a)
  (if gcrypt-ok?
      (zero? (gcry_cipher_algo_info a GCRYCTL_TEST_ALGO #f #f))
      #f))

(define-gcrypt gcry_cipher_final
  (_fun _gcry_cipher_hd (_int = GCRYCTL_FINALIZE) (_pointer = #f) (_size = 0) -> _gcry_error)
  #:c-id gcry_cipher_ctl
  #:fail (lambda () void))

;; ----

(define GCRY_WEAK_RANDOM        0)
(define GCRY_STRONG_RANDOM      1)
(define GCRY_VERY_STRONG_RANDOM 2)

(define-gcrypt gcry_randomize
  (_fun _pointer _size _int -> _void))

(define-gcrypt gcry_create_nonce
  (_fun _pointer _size -> _void))

;; ----

(define-cpointer-type _gcry_mpi)

(define-gcrypt gcry_mpi_release
  (_fun _gcry_mpi -> _void)
  #:wrap (deallocator))

(define-gcrypt gcry_mpi_new
  (_fun (_uint = 0) -> _gcry_mpi)
  #:wrap (allocator gcry_mpi_release))

(define-gcrypt gcry_mpi_powm
  (_fun _gcry_mpi _gcry_mpi _gcry_mpi _gcry_mpi -> _void))

(define-gcrypt gcry_mpi_sub_ui
  (_fun _gcry_mpi _gcry_mpi _ulong -> _void))

(define-gcrypt gcry_mpi_invm
  (_fun _gcry_mpi _gcry_mpi _gcry_mpi -> _bool))

(define-gcrypt gcry_mpi_get_nbits
  (_fun _gcry_mpi -> _uint))

(define-gcrypt gcry_mpi_scan
  (_fun (fmt buf) ::
        (result : (_ptr o _gcry_mpi))
        (fmt    : _int) ;; = GCRYMPI_FMT_USG
        (buf    : _bytes)
        (len    : _size = (bytes-length buf))
        (nread  : _pointer = #f) ;; (_ptr o _size)
        -> (status : _gcry_error)
        -> (values status result))
  #:wrap (compose (allocator gcry_mpi_release) check2))

(define-gcrypt gcry_mpi_print
  (_fun (fmt mpi buf) ::
        (fmt : _int) ;; = GCRYMPI_FMT_USG
        (buf : _bytes)
        (len : _size = (bytes-length buf))
        (nwrote : (_ptr o _size))
        (mpi : _gcry_mpi)
        -> (status : _gcry_error)
        -> (values status nwrote))
  #:wrap check2)

(define-gcrypt gcry_mpi_set_opaque_copy
  (_fun _gcry_mpi _pointer _uint -> _gcry_mpi))

(define (base256->mpi buf)
  (gcry_mpi_scan GCRYMPI_FMT_USG buf))

(define (mpi->base256 mpi)
  (define len (quotient (+ 7 (gcry_mpi_get_nbits mpi)) 8))
  (define buf (make-bytes len))
  (define len2 (gcry_mpi_print GCRYMPI_FMT_USG mpi buf))
  (subbytes buf 0 len2))

;; ----

(define-cpointer-type _gcry_sexp)

(define-gcrypt gcry_sexp_release
  (_fun _gcry_sexp -> _void)
  #:wrap (deallocator))

(define-gcrypt gcry_sexp_new
  (_fun (buf) ::
        (result  : (_ptr o _gcry_sexp))
        (buf     : _bytes)
        (buflen  : _size = (bytes-length buf))
        (autofmt : _int = 0)
        -> (status : _gcry_error)
        -> (values status result))
  #:wrap (compose (allocator gcry_sexp_release) check2))

(define-gcrypt gcry_sexp_build
  (_fun (fmt . args) ::
        (result : (_ptr o _gcry_sexp/null))
        (erroff : (_ptr o _size))
        (fmt    : _string/utf-8)
        (arg0 : _pointer = (get-sexp-build-arg args 0))
        (arg1 : _pointer = (get-sexp-build-arg args 1))
        (arg2 : _pointer = (get-sexp-build-arg args 2))
        (arg3 : _pointer = (get-sexp-build-arg args 3))
        (arg4 : _pointer = (get-sexp-build-arg args 4))
        (arg5 : _pointer = (get-sexp-build-arg args 5))
        -> (status : _gcry_error)
        -> (values status result))
  #:c-id gcry_sexp_build
  #:wrap (compose (allocator gcry_sexp_release) check2))

(define-gcrypt gcry_sexp_build/%b
  (_fun (fmt arg) ::
        (result : (_ptr o _gcry_sexp/null))
        (erroff : (_ptr o _size))
        (fmt : _string/utf-8)
        (len : _int = (bytes-length arg))
        (arg : _bytes)
        -> (status : _gcry_error)
        -> (values status result))
  #:c-id gcry_sexp_build
  #:wrap (compose (allocator gcry_sexp_release) check2))

(define-gcrypt gcry_sexp_build/%u
  (_fun (fmt arg) ::
        (result : (_ptr o _gcry_sexp/null))
        (erroff : (_ptr o _size))
        (fmt : _string/utf-8)
        (arg : _uint)
        -> (status : _gcry_error)
        -> (values status result))
  #:c-id gcry_sexp_build
  #:wrap (compose (allocator gcry_sexp_release) check2))

(define (get-sexp-build-arg args n)
  (and (> (length args) n) (list-ref args n)))

(define-gcrypt gcry_sexp_find_token
  (_fun (sexp : _gcry_sexp)
        (token : _string/utf-8)
        (size  : _size = (string-utf-8-length token))
        -> _gcry_sexp/null)
  #:wrap (allocator gcry_sexp_release))

(define-gcrypt gcry_sexp_nth_data
  (_fun (sexp  : _gcry_sexp)
        (index : _int)
        (len   : (_ptr o _size))
        -> (ptr : _pointer)
        -> (and ptr
                (let ([buf (make-bytes len)])
                  (memmove buf ptr len)
                  buf))))

(define GCRYMPI_FMT_HEX 4)
(define GCRYMPI_FMT_USG 5)

(define-gcrypt gcry_sexp_nth_mpi
  (_fun (sexp  : _gcry_sexp)
        (index : _int)
        (fmt   : _int = GCRYMPI_FMT_USG)
        -> _gcry_mpi/null)
  #:wrap (allocator gcry_mpi_release))

(define GCRYSEXP_FMT_CANON 1)
(define GCRYSEXP_FMT_ADVANCED 3)

(define-gcrypt gcry_sexp_sprint
  (_fun (sexp buf mode) ::
        (sexp : _gcry_sexp)
        (mode : _int)
        (buf  : _bytes)
        (len  : _size = (if buf (bytes-length buf) 0))
        -> _size))

(define (gcry_sexp->bytes s)
  (let* ([n (gcry_sexp_sprint s #f GCRYSEXP_FMT_CANON)]
         [buf (make-bytes n)])
    (gcry_sexp_sprint s buf GCRYSEXP_FMT_CANON)
    (subbytes buf 0 (sub1 n))))

(define (gcry_sexp->string s)
  (let* ([n (gcry_sexp_sprint s #f GCRYSEXP_FMT_ADVANCED)]
         [buf (make-bytes n)])
    (gcry_sexp_sprint s buf GCRYSEXP_FMT_ADVANCED)
    (bytes->string/utf-8 buf #f 0 (sub1 n))))

;; ----

(define-gcrypt gcry_pk_testkey
  (_fun _gcry_sexp -> _gcry_error)
  #:wrap check)

(define-gcrypt gcry_pk_encrypt
  (_fun (data pubkey) ::
        (result : (_ptr o _gcry_sexp/null))
        (data   : _gcry_sexp)
        (pubkey : _gcry_sexp)
        -> (status : _gcry_error)
        -> (values status result))
  #:wrap (compose (allocator gcry_sexp_release) check2))

(define-gcrypt gcry_pk_decrypt
  (_fun (data privkey) ::
        (result  : (_ptr o _gcry_sexp/null))
        (data    : _gcry_sexp)
        (privkey : _gcry_sexp)
        -> (status : _gcry_error)
        -> (values status result))
  #:wrap (compose (allocator gcry_sexp_release)
                  (lambda (f)
                    (lambda args
                      (let-values ([(status result) (apply f args)])
                        (and (= status GPG_ERR_NO_ERROR) result))))))

(define-gcrypt gcry_pk_sign
  (_fun (data privkey) ::
        (result : (_ptr o _gcry_sexp/null))
        (data   : _gcry_sexp)
        (privkey : _gcry_sexp)
        -> (status : _gcry_error)
        -> (values status result))
  #:wrap (compose (allocator gcry_sexp_release) check2))

(define-gcrypt gcry_pk_verify
  (_fun (sig data pubkey) ::
        (sig  : _gcry_sexp)
        (data : _gcry_sexp)
        (pubkey : _gcry_sexp)
        -> (status : _gcry_error)
        -> (cond [(= status GPG_ERR_NO_ERROR)
                  (values status #t)]
                 [(= (gcry_error-code status) GPG_ERR_BAD_SIGNATURE)
                  ;; Convert status to avoid raising exn, return #f for "not verified"
                  (values GPG_ERR_NO_ERROR #f)]
                 [else
                  (eprintf "got status ~s\n" status)
                  (values status #f)]))
  #:wrap check2)

(define-gcrypt gcry_pk_get_nbits
  (_fun _gcry_sexp -> _uint))

(define-gcrypt gcry_pk_genkey
  (_fun (params) ::
        (result : (_ptr o _gcry_sexp/null))
        (params : _gcry_sexp)
        -> (status : _gcry_error)
        -> (values status result))
  #:wrap (compose (allocator gcry_sexp_release) check2))

(define GCRY_PK_RSA   1)   ;; RSA
(define GCRY_PK_DSA   17)  ;; Digital Signature Algorithm
(define GCRY_PK_ECC   18)  ;; Generic ECC
(define GCRY_PK_ELG   20)  ;; Elgamal
(define GCRY_PK_ECDSA 301) ;; (only for external use)
(define GCRY_PK_ECDH  302) ;; (only for external use)
(define GCRY_PK_EDDSA 303) ;; (only for external use)

;; Returns NULL for unknown curve
(define-gcrypt gcry_pk_get_param
  (_fun _int _bytes -> _gcry_sexp/null)
  #:c-id gcry_pk_get_param)

(define-gcrypt gcry-curve-ok?
  (_fun (_int = GCRY_PK_ECC) _symbol -> (r : _gcry_sexp/null) -> (and r #t))
  #:c-id gcry_pk_get_param
  #:fail (lambda () (lambda (c) #f)))

(define gcrypt-curves
  (filter gcry-curve-ok?
          '(secp192r1 secp224r1 secp256r1 secp384r1 secp521r1
            secp256k1
            brainpoolP160r1 brainpoolP192r1 brainpoolP224r1 brainpoolP256r1
            brainpoolP320r1 brainpoolP384r1 brainpoolP512r1)))

(define ed25519-ok? (gcry-curve-ok? 'Ed25519))
(define x25519-ok?  (gcry-curve-ok? 'Curve25519))

;; ----------------------------------------

(define-cpointer-type _gcry_ctx)
(define-cpointer-type _gcry_mpi_point)

(define-gcrypt gcry_mpi_point_release
  (_fun (point : _gcry_mpi_point) -> _void)
  #:wrap (deallocator))
(define-gcrypt gcry_mpi_point_new
  (_fun (nbits : _uint = 0) -> _gcry_mpi_point)
  #:wrap (allocator gcry_mpi_point_release))

(define-gcrypt gcry_ctx_release
  (_fun (ctx : _gcry_ctx) -> _void)
  #:wrap (deallocator))
(define-gcrypt gcry_mpi_ec_new
  (_fun (ctx : (_ptr o _gcry_ctx)) (kparam : _pointer = #f) (curve : _bytes)
        -> (s : _gcry_error) -> (values s ctx))
  #:wrap (compose (allocator gcry_ctx_release) check2))

(define-gcrypt gcry_mpi_ec_get_mpi
  (_fun (name : _symbol) (ctx : _gcry_ctx) (copy : _int = 1)
        -> _gcry_mpi)
  #:wrap (allocator gcry_mpi_release))
(define-gcrypt gcry_mpi_ec_get_point
  (_fun (name : _symbol) (ctx : _gcry_ctx) (copy : _int = 1)
        -> _gcry_mpi_point)
  #:wrap (allocator gcry_mpi_point_release))
(define-gcrypt gcry_mpi_ec_set_mpi
  (_fun (name : _symbol) (value : _gcry_mpi) (ctx : _gcry_ctx)
        -> _gcry_error)
  #:wrap check)
(define-gcrypt gcry_mpi_ec_set_point
  (_fun (name : _symbol) (value : _gcry_mpi_point) (ctx : _gcry_ctx)
        -> _gcry_error)
  #:wrap check)

(define-gcrypt gcry_mpi_ec_mul
  (_fun _gcry_mpi_point _gcry_mpi _gcry_mpi_point _gcry_ctx
        -> _void))

(define-gcrypt gcry_mpi_ec_decode_point
  (_fun (point : _gcry_mpi_point) (value : _gcry_mpi) (ctx : _gcry_ctx)
        -> (s : _gcry_error))
  #:wrap check)

(define-gcrypt decode-point-ok? _fpointer
  #:c-id gcry_mpi_ec_decode_point
  #:fail (lambda () #f) #:wrap (lambda (v) (and v #t)))

(define-gcrypt gcry_mpi_ec_curve_point
  (_fun (w : _gcry_mpi_point) (ctx : _gcry_ctx) -> _bool))

(define GCRY_PK_GET_PUBKEY 1)
(define GCRY_PK_GET_SECKEY 2)

(define-gcrypt gcry_pubkey_get_sexp
  (_fun (sexp : (_ptr o _gcry_sexp)) (mode : _int) (ctx : _gcry_ctx)
        -> (s : _gcry_error) -> (values s sexp))
  #:wrap (compose (allocator gcry_sexp_release) check2))
