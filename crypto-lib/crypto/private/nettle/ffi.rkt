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
         (only-in '#%foreign ffi-obj)
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
  ([name         _string/utf-8]
   [context_size _uint]
   [digest_size  _uint]
   [block_size   _uint]
   [init         _nettle_hash_init_func]
   [update       _nettle_hash_update_func]
   [digest       _nettle_hash_digest_func]))

;; struct nettle_hash *nettle_hashes[], array terminated by NULL
(define nettle_hashes (ffi-obj #"nettle_hashes" libnettle))

(define nettle-hashes
  (let ([ptr nettle_hashes])
    (let loop ([i 0])
      (let ([next (ptr-ref ptr _nettle_hash-pointer/null i)])
        (if next
            (cons (list (nettle_hash-name next) next)
                  (loop (add1 i)))
            null)))))

;; ----

(define-nettle nettle_hmac_set_key
  (_fun (outer inner state hash key) ::
        (outer : _HASH_CTX)
        (inner : _HASH_CTX)
        (state : _HASH_CTX)
        (hash  : _nettle_hash-pointer)
        (keylen : _uint = (bytes-length key))
        (key   : _pointer)
        -> _void))

(define-nettle nettle_hmac_update
  (_fun (state hash inbuf inlen) ::
        (state : _HASH_CTX)
        (hash  : _nettle_hash-pointer)
        (inlen : _uint)
        (inbuf : _pointer)
        -> _void))

(define-nettle nettle_hmac_digest
  (_fun (outer inner state hash outbuf outlen) ::
        (outer  : _HASH_CTX)
        (inner  : _HASH_CTX)
        (state  : _HASH_CTX)
        (hash   : _nettle_hash-pointer)
        (outlen : _uint)
        (outbuf : _pointer)
        -> _void))

;; ----

(define-cpointer-type _CIPHER_CTX)

(define _nettle_set_key_func
  (_fun _CIPHER_CTX _uint _pointer -> _void))

(define _nettle_crypt_func
  (_fun _CIPHER_CTX _uint _pointer _pointer -> _void))

(define-cstruct _nettle_cipher
  ([name            _string/utf-8]
   [context_size    _uint]
   [block_size      _uint]
   [key_size        _uint]
   [set_encrypt_key _nettle_set_key_func]
   [set_decrypt_key _nettle_set_key_func]
   [encrypt         _nettle_crypt_func]
   [decrypt         _nettle_crypt_func]))

;; struct nettle_cipher *nettle_ciphers[], array terminated by NULL
(define nettle_ciphers (ffi-obj #"nettle_ciphers" libnettle))

(define nettle-regular-ciphers
  (let ([ptr nettle_ciphers])
    (let loop ([i 0])
      (let ([next (ptr-ref ptr _nettle_cipher-pointer/null i)])
        (if next
            (cons (list (nettle_cipher-name next) next)
                  (loop (add1 i)))
            null)))))

;; nettle_ciphers omits ciphers with any irregularity;
;; create dummy entries for them (with name=#f to avoid GC problems)

(define BLOWFISH_ROUNDS 16)
(define BLOWFISH_CONTEXT_SIZE (+ (* 4 4 256) (* 4 (+ 2 BLOWFISH_ROUNDS))))
(define BLOWFISH_BLOCK_SIZE 8)
(define BLOWFISH_KEY_SIZE 16) ;; reasonable default
(define-nettle nettle_blowfish_set_key _nettle_set_key_func)
(define-nettle nettle_blowfish_encrypt _nettle_crypt_func #:fail (lambda () #f))
(define-nettle nettle_blowfish_decrypt _nettle_crypt_func #:fail (lambda () #f))

(define blowfish-cipher
  (and nettle_blowfish_encrypt
       (make-nettle_cipher
        #f BLOWFISH_CONTEXT_SIZE BLOWFISH_BLOCK_SIZE BLOWFISH_KEY_SIZE
        nettle_blowfish_set_key nettle_blowfish_set_key
        nettle_blowfish_encrypt nettle_blowfish_decrypt)))

(define SALSA20_CONTEXT_SIZE (* 4 16))
(define SALSA20_KEY_SIZE 32)
(define SALSA20_BLOCK_SIZE 64)
(define SALSA20_IV_SIZE 8)
(define-nettle nettle_salsa20_set_key _nettle_set_key_func)
(define-nettle nettle_salsa20_set_iv  _nettle_set_key_func)
(define-nettle nettle_salsa20_crypt _nettle_crypt_func #:fail (lambda () #f))
(define-nettle nettle_salsa20r12_crypt _nettle_crypt_func #:fail (lambda () #f))

(define salsa20-cipher
  (and nettle_salsa20_crypt
       (list "salsa20"
             (make-nettle_cipher
              #f SALSA20_CONTEXT_SIZE SALSA20_BLOCK_SIZE SALSA20_KEY_SIZE
              nettle_salsa20_set_key nettle_salsa20_set_key
              nettle_salsa20_crypt nettle_salsa20_crypt)
             `(set-iv ,nettle_salsa20_set_iv))))

(define salsa20r12-cipher
  (and nettle_salsa20r12_crypt
       (list "salsa20r12"
             (make-nettle_cipher
              #f SALSA20_CONTEXT_SIZE SALSA20_BLOCK_SIZE SALSA20_KEY_SIZE
              nettle_salsa20_set_key nettle_salsa20_set_key
              nettle_salsa20r12_crypt nettle_salsa20r12_crypt)
             `(set-iv ,nettle_salsa20_set_iv))))

(define nettle-more-ciphers
  (append nettle-regular-ciphers
          (filter values
                  (list blowfish-cipher
                        salsa20-cipher
                        salsa20r12-cipher))))

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

