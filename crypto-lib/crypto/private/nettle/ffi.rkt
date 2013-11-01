;; Copyright 2013 Ryan Culpepper
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

(define libnettle (ffi-lib "libnettle" '("4" #f)))

(define-ffi-definer define-nettle libnettle
  #:default-make-fail make-not-available)

;; ----

(define-cpointer-type _HASH_CTX)

(define _nettle_hash_init_func
  (_fun _HASH_CTX -> _void))
(define _nettle_hash_update_func
  (_fun _HASH_CTX _uint _pointer -> _void))
(define _nettle_hash_digest_func
  (_fun _HASH_CTX _uint _pointer -> _void))

(define-cstruct _nettle_hash
  ([name : _string]
   [context_size : _uint]
   [digest_size : _uint]
   [block_size : _uint]
   [init : _nettle_hash_init_func]
   [update : _nettle_hash_update_func]
   [digest : _nettle_hash_digest_func]))

(define-nettle nettle_hashes _pointer) ;; struct nettle_hash **nettle_hashes



;; ----

(define-cpointer-type _CIPHER_CTX)

(define _nettle_set_key_func
  (_fun _CIPHER_CTX _uint _pointer -> _void))

(define _nettle_crypt_func
  (_fun _CIPHER_CTX _uint _pointer _pointer -> _void))

(define-cstruct _nettle_cipher
  ([name : _string]
   [context_size : _uint]
   [key_size : _uint]
   [set_encrypt_key : _nettle_set_key_func]
   [set-decrypt_key : _nettle_set_key_func]
   [encrypt : _nettle_crypt_func]
   [decrypt : _nettle_crypt_func]))

(define-nettle nettle_ciphers _pointer) ;; struct nettle_cipher **nettle_ciphers

;; ----

;; CBC_CTX(type, size) = { type ctx; uint8_t iv[size]; }
(define-cpointer-type _CBC_CTX)

(define-nettle nettle_cbc_encrypt
  (_fun (ctx     : _CIPHER_CTX)
        (encrypt : _nettle_crypt_func)
        (blksize : _uint)
        (iv      : _pointer)
        (length  : _uint)
        (dst     : _pointer)
        (src     : _pointer)
        -> _void))

(define-nettle nettle_cbc_decrypt
  (_fun (ctx     : _CBC_CTX)
        (decrypt : _nettle_crypt_func)
        (blksize : _uint)
        (iv      : _pointer)
        (length  : _uint)
        (dst     : _pointer)
        (src     : _pointer)
        -> _void))

;; CTR_CTX(type, size) = { type ctx; uint8_t ctr[size]; }
(define-cpointer-type _CTR_CTX)

(define-nettle nettle_ctr_crypt
  (_fun (ctx     : _CTR_CTX)
        (crypt   : _nettle_crypt_func)
        (blksize : _uint)
        (ctr     : _pointer)
        (length  : _uint)
        (dst     : _pointer)
        (src     : _pointer)
        -> _void))

