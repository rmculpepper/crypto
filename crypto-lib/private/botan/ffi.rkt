;; Copyright 2018 Ryan Culpepper
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
         ffi/unsafe/alloc
         ffi/unsafe/define)
(provide (protect-out (all-defined-out)))

(define libbotan (ffi-lib "libbotan-2" '(#f "4") #:fail (lambda () #f)))

(define-ffi-definer define-bo libbotan
  #:default-make-fail make-not-available)

(define botan-ok? (and libbotan #t))

(define-bo botan_ffi_api_version (_fun -> _uint32))
(define-bo botan_version_string (_fun -> _string/utf-8))
(define-bo botan_version_major (_fun -> _uint32))
(define-bo botan_version_minor (_fun -> _uint32))
(define-bo botan_version_patch (_fun -> _uint32))
(define-bo botan_version_datestamp (_fun -> _uint32))

;; ----

(define-cpointer-type _botan_hash)

(define-bo botan_hash_destroy (_fun _botan_hash -> _void)
  #:wrap (deallocator))
(define-bo botan_hash_init
  (_fun (h : (_ptr o _botan_hash/null)) _string/utf-8 (_uint32 = 0) -> (r : _int)
        -> (and (zero? r) h))
  #:wrap (allocator botan_hash_destroy))

(define-bo botan_hash_copy_state
  (_fun (d : (_ptr o _botan_hash/null)) _botan_hash -> (r : _int) -> (and (zero? r) d)))
(define-bo botan_hash_clear (_fun _botan_hash -> _int))
(define-bo botan_hash_output_length
  (_fun _botan_hash (len : (_ptr o _size)) -> (r : _int) -> (and (zero? r) len)))
(define-bo botan_hash_update (_fun _botan_hash _pointer _size -> _int))
(define-bo botan_hash_final (_fun _botan_hash _pointer -> _int))

;; ----

(define botan-macs
  '("GMAC(?)"
    "HMAC(?)"
    ))

(define-cpointer-type _botan_mac)

(define-bo botan_mac_destroy (_fun _botan_mac -> _void)
  #:wrap (deallocator))
(define-bo botan_mac_init (_fun _string/utf-8 (_uint32 = 0) -> _botan_mac/null)
  #:wrap (allocator botan_mac_destroy))

(define-bo botan_mac_clear (_fun _botan_mac -> _void))
(define-bo botan_mac_output_length (_fun _botan_mac -> _size))
(define-bo botan_mac_set_key (_fun _botan_mac _pointer _size -> _int))
(define-bo botan_mac_update (_fun _botan_mac _pointer _size -> _int))
(define-bo botan_mac_final (_fun _botan_mac _pointer (_pointer = #f) -> _int))

;; ----

(define-cpointer-type _botan_cipher)

(define FLAG_ENCRYPT 0)
(define FLAG_DECRYPT 1)

(define-bo botan_cipher_destroy (_fun _botan_cipher -> _int)
  #:wrap (deallocator))
(define-bo botan_cipher_init
  (_fun (c : (_ptr o _botan_cipher/null)) _string/utf-8 _uint32 -> (r : _int) -> (and (zero? r) c))
  #:wrap (allocator botan_cipher_destroy))

(define-bo botan_cipher_valid_nonce_length (_fun _botan_cipher _size -> _int))
(define-bo botan_cipher_get_tag_length
  (_fun _botan_cipher (len : (_ptr o _size)) -> (r : _int) -> (and (zero? r) len)))
(define-bo botan_cipher_get_default_nonce_length
  (_fun _botan_cipher (len : (_ptr o _size)) -> (r : _int) -> (and (zero? r) len)))
(define-bo botan_cipher_get_update_granularity
  (_fun _botan_cipher (g : (_ptr o _size)) -> (r : _int) -> (and (zero? r) g)))
(define-bo botan_cipher_query_keylen
  (_fun _botan_cipher (lo : (_ptr o _size)) (hi : (_ptr o _size)) -> (r : _int)
        -> (and (zero? r) (cons lo hi))))
(define-bo botan_cipher_set_key (_fun _botan_cipher _pointer _size -> _int))
(define-bo botan_cipher_set_associated_data (_fun _botan_cipher _pointer _size -> _int))
(define-bo botan_cipher_start (_fun _botan_cipher _pointer _size -> _int))
(define-bo botan_cipher_clear (_fun _botan_cipher -> _int))

(define FLAG_FINAL #x01)

(define-bo botan_cipher_update
  (_fun (ci flags outbuf outlen inbuf inlen) ::
        (ci : _botan_cipher)
        (flags : _uint32)
        (outbuf : _pointer) (outlen : _size)
        (outwrote : (_ptr o _size))
        (inbuf : _pointer)
        (inlen : _size)
        (inread : (_ptr o _size))
        -> (r : _int)
        -> (values r outwrote inread)))
