;; Copyright 2012-2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/list)
(provide (all-from-out (submod "." logger))
         crypto-entry-point
         with-crypto-entry
         crypto-who
         crypto-error
         internal-error
         impl-limit-error

         check-bytes
         err/no-impl
         err/bad-signature-pad
         err/bad-encrypt-pad
         err/missing-digest
         err/not-fixed-digest
         err/crypt-failed
         err/auth-decrypt-failed
         err/no-curve
         err/off-curve)

(module logger racket/base
  (provide (all-defined-out))
  (define-logger crypto))
(require (submod "." logger))

;; Error conventions:
;; - use (about) for reporting context
;; - order: EXPECTED, GIVEN, CONTEXT

(define crypto-entry-point (gensym))

(define-syntax-rule (with-crypto-entry who body ...)
  (with-continuation-mark crypto-entry-point who (let () body ...)))

(define (crypto-who)
  (define entry-points
    (continuation-mark-set->list (current-continuation-marks) crypto-entry-point))
  (if (pair? entry-points) (last entry-points) 'crypto))

(define (crypto-error #:for [forvalue #f] #:in [impl #f] fmt . args)
  (crypto-error* fmt args #:for forvalue #:in impl))

(define (internal-error #:in [in #f] fmt . args)
  (crypto-error* fmt args #:prefix "internal error: " #:in in))

(define (impl-limit-error #:in [in #f] fmt . args)
  (crypto-error* fmt args #:prefix "implementation limitation: " #:in in))

(define (crypto-error* fmt args
                       #:prefix [prefix ""]
                       #:for [forvalue #f]
                       #:in [invalue #f])
  (define (line label val)
    (cond [(string? val) (format "\n  ~a: ~a" label val)]
          [val (format "\n  ~a: ~e" label val)]
          [else ""]))
  (error (crypto-who) "~a~a~a~a"
         prefix
         (apply format fmt args)
         (line "for" forvalue)
         (line "in" invalue)))

;; ----

(define (check-bytes what v len [hilen len] #:for [forobj #f] #:in [inobj #f])
  (unless (<= len (bytes-length v) hilen)
    (define wanted
      (cond [(= len hilen) (format "~s bytes" len)]
            [else (format "between ~s and ~s bytes (inclusive)" len hilen)]))
    (define impl-note (if inobj " (implementation limit)" ""))
    (crypto-error "wrong size for ~a~a\n  expected: ~a\n  given: ~s bytes"
                  what impl-note wanted (bytes-length v)
                  #:for forobj #:in inobj)))

(define (err/no-impl [obj #f])
  (internal-error "unimplemented" #:in obj))

(define (err/bad-signature-pad impl pad)
  (crypto-error "signature padding not supported\n  padding: ~e" pad #:in impl))
(define (err/bad-encrypt-pad impl pad)
  (crypto-error "encryption padding not supported\n  padding: ~e" pad #:in impl))

(define (err/missing-digest spec)
  (crypto-error "could not get digest implementation\n  digest: ~e" spec))

(define (err/not-fixed-digest di #:in [impl #f])
  (crypto-error "variable-sized digest or XOF not allowed\n  digest: ~e"
                di #:in impl))

(define (err/crypt-failed enc? auth?)
  (crypto-error "~a~a failed"
                (if auth? "authenticated " "")
                (if enc? "encryption" "decryption")))

(define (err/auth-decrypt-failed)
  (err/crypt-failed #f #t))

(define (err/no-curve curve [obj #f])
  (crypto-error "given named curve not supported\n  curve: ~e" curve #:for obj))

(define (err/off-curve what)
  (crypto-error "invalid ~a (point not on curve)" what))
