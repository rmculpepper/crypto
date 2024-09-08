;; Copyright 2014-2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

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
