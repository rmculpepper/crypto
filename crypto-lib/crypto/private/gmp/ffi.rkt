;; Copyright 2014 Ryan Culpepper
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

(define-ffi-definer define-gmp (ffi-lib "libgmp"))

(define-cstruct _mpz_struct
  ([alloc _int]
   [size  _int]
   [limbs _pointer]))

;; Bleh: typedef struct mpz_struct mpz_t[1]
(define _mpz_t _mpz_struct-pointer)

(define-gmp __gmpz_init (_fun _mpz_t -> _void))
(define-gmp __gmpz_clear (_fun _mpz_t -> _void) #:wrap (deallocator))

(define new-mpz
  ((allocator __gmpz_clear)
   (lambda ()
     (define z (make-mpz_struct 0 0 #f))
     (__gmpz_init z)
     z)))

(define-gmp __gmpz_set
  (_fun _mpz_t _mpz_t -> _void))

(define-gmp __gmpz_set_si
  (_fun _mpz_t _long -> _void))

(define-gmp __gmp_snprintf
  (_fun (buf : _bytes)
        (len : _size = (bytes-length buf))
        (fmt : _bytes)
        (arg : _pointer)
        -> _int))

(define-gmp __gmpz_set_str
  (_fun (dest : _mpz_t)
        (str : _bytes)
        (base : _int)
        -> _bool))

(define-gmp __gmp_sscanf
  (_fun (buf : _bytes)
        (fmt : _bytes)
        (arg : _pointer)
        -> _int))

(define (mpz->hex z)
  (define size (__gmp_snprintf #"" #"%Zx" z))
  (define buf (make-bytes (add1 size)))
  (define size2 (__gmp_snprintf buf #"%Zx" z))
  (subbytes buf 0 size2))

(define (hex->mpz buf)
  (define z (new-mpz))
  ;; make absolutely sure \0-terminated
  (or (__gmpz_set_str z (bytes-append buf #"\0") 16)
      (error 'hex->mpz "failed"))
  z)

(define-gmp __gmpz_sizeinbase
  (_fun _mpz_t _int -> _size))

(define-gmp __gmpz_export
  (_fun (buf size src) ::
        (buf : _bytes)
        (len : (_ptr o _size))
        (order : _int = 1) ;; most significant chunk first
        (size : _size)
        (endian : _int = 1) ;; big endian (bytes w/in chunk)
        (nails : _size = 0) ;; no unused bits per chunk
        (src : _mpz_t)
        -> _void
        -> len))

;; If signed? is true, then format as "signed twos-complement
;; base-256" ---that is, make sure leading bit is zero so will be
;; interpreted as nonnegative.
;; NOTE: only nonnegative z handled!
(define (mpz->bin z [signed? #f])
  (define size-in-bits (__gmpz_sizeinbase z 2))
  (define size-in-bytes (quotient (+ size-in-bits (if signed? 8 7)) 8))
  (define buf (make-bytes (add1 size-in-bytes)))
  (define len (__gmpz_export buf 1 z))
  (subbytes buf 0 len))

(define-gmp __gmpz_import
  (_fun (dst count size src) ::
        (dst : _mpz_t)
        (count : _size)
        (order : _int = 1) ;; most significant word first
        (size : _size)
        (endian : _int = 1) ;; big endian (bytes w/in chunk)
        (nails : _size = 0) ;; no unused bits per chunk
        (src : _pointer)
        -> _void))

(define (bin->mpz buf)
  (define z (new-mpz))
  (__gmpz_import z (bytes-length buf) 1 buf)
  z)

(define-gmp __gmpz_cmp
  (_fun _mpz_t _mpz_t -> _int))

(define (mpz=? a b)
  (zero? (__gmpz_cmp a b)))
(define (mpz<? a b)
  (negative? (__gmpz_cmp a b)))
(define (mpz>? a b)
  (mpz<? b a))

(define-gmp __gmpz_powm
  (_fun (dst  : _mpz_t)
        (base : _mpz_t)
        (exp  : _mpz_t)
        (mod  : _mpz_t)
        -> _void))
