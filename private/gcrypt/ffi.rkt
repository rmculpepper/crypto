;; Copyright 2012 Ryan Culpepper
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
         ffi/unsafe/atomic)
(provide (protect-out (all-defined-out)))

(define libgcrypt (ffi-lib "libgcrypt" '("11" #f)))

(define-ffi-definer define-gcrypt libgcrypt
  #:default-make-fail make-not-available)

;; ----

(define-ffi-definer define-racket #f)
(define-racket scheme_make_sized_byte_string (_fun _pointer _intptr _bool -> _racket))

(define _gcry_error _uint)

(define GPG_ERR_NO_ERROR 0)

(define-gcrypt gcry_strerror (_fun _gcry_error -> _string))

(define ((check f) . args)
  (call-as-atomic
   (lambda ()
     (let ([status (apply f args)])
       (if (= status GPG_ERR_NO_ERROR)
           (void)
           (error 'libgcrypt "~a" (gcry_strerror status)))))))

(define ((check2 f) . args)
  (call-as-atomic
   (lambda ()
     (let-values ([(status result) (apply f args)])
       (if (= status GPG_ERR_NO_ERROR)
           result
           (error 'libgcrypt "~a" (gcry_strerror status)))))))

;; ----

(define _size _uintptr) ;; FIXME: ffi should provide _size
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

(define GCRY_MD_FLAG_SECURE    1) ;; Allocate all buffers in "secure" memory.
(define GCRY_MD_FLAG_HMAC      2) ;; Make an HMAC out of this algorithm.

(define GCRYCTL_TEST_ALGO      8)

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
  (zero? (gcry_md_algo_info a GCRYCTL_TEST_ALGO #f #f)))

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

(define GCRY_CIPHER_MODE_NONE    0) ;; Not yet specified.
(define GCRY_CIPHER_MODE_ECB     1) ;; Electronic codebook.
(define GCRY_CIPHER_MODE_CFB     2) ;; Cipher feedback.
(define GCRY_CIPHER_MODE_CBC     3) ;; Cipher block chaining.
(define GCRY_CIPHER_MODE_STREAM  4) ;; Used with stream ciphers.
(define GCRY_CIPHER_MODE_OFB     5) ;; Outer feedback.
(define GCRY_CIPHER_MODE_CTR     6) ;; Counter.
(define GCRY_CIPHER_MODE_AESWRAP 7) ;; AES-WRAP algorithm.

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

(define-gcrypt gcry_cipher_encrypt
  (_fun _gcry_cipher_hd _pointer _size _pointer _size -> _gcry_error)
  #:wrap check)

(define-gcrypt gcry_cipher_decrypt
  (_fun _gcry_cipher_hd _pointer _size _pointer _size -> _gcry_error)
  #:wrap check)

(define-gcrypt gcry_cipher_get_algo_keylen (_fun _int -> _size))
(define-gcrypt gcry_cipher_get_algo_blklen (_fun _int -> _size))

;; ----

(define GCRY_WEAK_RANDOM        0)
(define GCRY_STRONG_RANDOM      1)
(define GCRY_VERY_STRONG_RANDOM 2)

(define-gcrypt gcry_randomize
  (_fun _pointer _size _int -> _void))

(define-gcrypt gcry_create_nonce
  (_fun _pointer _size -> _void))
