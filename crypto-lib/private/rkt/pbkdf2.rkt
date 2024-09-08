;; Copyright 2012-2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/class
         "../common/common.rkt")
(provide pbkdf2-hmac
         pbkdf2)

;; References:
;; - http://tools.ietf.org/html/rfc2898
;; - http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf

;; Performance: for nettle and gcrypt, about x6 or x7 slowdown

(define (pbkdf2-hmac dimpl pass salt iterations key-size)
  (define hlen (send dimpl get-size)) ;; (digest-size dimpl)
  ;;(define (PRF text) (send dimpl hmac pass text))
  (define outbuf (make-bytes hlen))
  (define root-hctx (send dimpl new-hmac-ctx pass))
  (define (PRF text)
    ;; Use -copy, -update, -final! to avoid overhead from sync, state, etc
    (define hctx (send root-hctx -copy))
    (send hctx -update text 0 (bytes-length text))
    (send hctx -final! outbuf)
    outbuf)
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

  (shrink-bytes resultbuf wantlen))

#;
(define (bytes-xor! dest src len)
  (for ([i (in-range len)])
    (bytes-set! dest i (bitwise-xor (bytes-ref dest i) (bytes-ref src i)))))

(require racket/unsafe/ops)
(define (bytes-xor! dest src len)
  (for ([i (in-range len)])
    (unsafe-bytes-set! dest i
                       (unsafe-fxxor (unsafe-bytes-ref dest i)
                                     (unsafe-bytes-ref src i)))))
