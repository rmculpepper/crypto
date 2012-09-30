;; mzcrypto: libcrypto bindings for PLT-scheme
;; BN interface
;; 
;; (C) Copyright 2007-2009 Dimitris Vyzovitis <vyzo at media.mit.edu>
;; 
;; mzcrypto is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as published
;; by the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;; 
;; mzcrypto is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Lesser General Public License for more details.
;; 
;; You should have received a copy of the GNU Lesser General Public License
;; along with mzcrypto.  If not, see <http://www.gnu.org/licenses/>.
#lang racket/base
(require ffi/unsafe
         ffi/unsafe/alloc
         "libcrypto.rkt"
         "error.rkt"
         "util.rkt")
(provide (all-defined-out))

(define-cpointer-type _BIGNUM)

(define-crypto BN_free
  (_fun _BIGNUM
        -> _void)
  #:wrap (deallocator))

(define-crypto BN_new
  (_fun -> _BIGNUM)
  #:wrap (allocator BN_free))

(define-crypto BN_add_word
  (_fun _BIGNUM
        _ulong
        -> (result : _int)
        -> (check-error 'BN_add_word result)))

(define-crypto BN_dup
  (_fun _BIGNUM
        -> (result : _BIGNUM)
        -> (pointer/error 'BN_dup result)))

(define-crypto BN_num_bits
  (_fun _BIGNUM
        -> _int))

(define-crypto BN_bn2bin
  (_fun _BIGNUM
        _bytes
        -> _int))

(define-crypto BN_bin2bn
  (_fun (bs : _bytes)
        (_int = (bytes-length bs))
        (_pointer = #f)
        -> (result : _BIGNUM)
        -> (pointer/error 'BN_bin2bn result)))

(define (bn-size bn)
  (ceiling (/ (BN_num_bits bn) 8)))

(define (bn->bytes bn)
  (let ((bs (make-bytes (bn-size bn))))
    (shrink-bytes bs (BN_bn2bin bn bs))))
  
(define (bytes->bn bs)
  (BN_bin2bn bs))
