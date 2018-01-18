;; Copyright 2014-2018 Ryan Culpepper
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
(require binaryio/integer)
(provide (all-defined-out))

(define (unsigned->base256 n)
  (unless (exact-nonnegative-integer? n)
    (raise-argument-error 'unsigned->base256 "exact-nonnegative-integer?" n))
  (integer->bytes n (integer-bytes-length n #f) #f #t))

(define (signed->base256 n)
  (unless (exact-integer? n)
    (raise-argument-error 'signed->base256 "exact-integer?" n))
  (integer->bytes n (integer-bytes-length n #t) #t #t))

(define (base256->unsigned bs)
  (bytes->integer bs #f #t))

(define (base256->signed bs)
  (bytes->integer bs #t #t))

(define (base256-unsigned->signed b)
  (signed->base256 (base256->unsigned b)))
