;; Copyright 2012-2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require crypto
         crypto/all)
(provide (all-defined-out))

;; let's not exhaust our entropy pool on testing
(define (semirandom-bytes len)
  (let ([bs (make-bytes len)])
    (for ([i (in-range len)])
      (bytes-set! bs i (random 256)))
    bs))

(define (semirandom-bytes/no-nul len)
  (let ([bs (make-bytes len)])
    (for ([i (in-range len)])
      (bytes-set! bs i (add1 (random 255))))
    bs))

(define (semirandom-bytes/alpha len)
  (let ([bs (make-bytes len)])
    (for ([i (in-range len)])
      (bytes-set! bs i (+ 65 (random 26))))
    bs))

;; ----------------------------------------

(define (names->factories factory-names)
  (cond [(pair? factory-names)
         (define fnames (map string->symbol factory-names))
         (filter (lambda (f) (memq (factory-name f) fnames))
                 all-factories)]
        [else all-factories]))
