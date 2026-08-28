;; Copyright 2012-2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require brandx
         crypto)
(provide pbkdf2-hmac
         pbkdf2)

;; References:
;; - http://tools.ietf.org/html/rfc2898
;; - http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf

;; Performance: for nettle and gcrypt, about x6 or x7 slowdown

(define (pbkdf2-hmac hmaci pass salt iterations key-size)
  (define hlen (digest-size hmaci))
  (define (PRF text) (digest hmaci text #:key pass))
  (pbkdf2 PRF hlen pass salt iterations key-size))

(define (pbkdf2 PRF hlen password salt iterations wantlen)
  ;; wantlen = desired length of key to generate
  (define wantblocks (quotient (+ wantlen hlen -1) hlen))

  ;; F : Nat -> Bytes
  (define (F i) ;; in RFC: F(P, S, c, i); note i starts at 1
    (define block (make-bytes hlen 0))
    (define PRFin (make-bytes hlen))
    ;; peel off first iteration w/ different-sized input
    (define PRFout (PRF (bytes-append salt (integer->integer-bytes i 4 #f #t))))
    (bytes-xor! block PRFout hlen)
    (bytes-copy! PRFin 0 PRFout 0 hlen)
    (for ([j (in-range 1 iterations)])
      (define PRFout (PRF PRFin))
      (bytes-xor! block PRFout hlen)
      (bytes-copy! PRFin 0 PRFout 0 hlen))
    block)

  (define resultbuf
    (apply bytes-append
           (for/list ([i (in-range 1 (add1 wantblocks))]) (F i))))
  (subbytes resultbuf 0 wantlen))

(define (bytes-xor! dest src len)
  (for ([i (in-range len)])
    (bytes-set! dest i (bitwise-xor (bytes-ref dest i) (bytes-ref src i)))))
