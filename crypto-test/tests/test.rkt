;; Copyright 2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/class
         crypto
         crypto/all
         checkers
         "digest.rkt"
         "cipher.rkt"
         "kdf.rkt"
         "pkey.rkt"
         "util.rkt")

;; test-all : (Listof Factory) (Listof Symbol) -> Void
(define (test-all factories algos)
  (run-tests (lambda () (test-all-factories factories algos))
             #:progress? #t))

;; test-all-factories : (Listof Factory) (Listof Symbol) -> Void
(define (test-all-factories factories algos)
  (for ([factory (in-list factories)])
    (test-factory factory algos))
  (xtest-factories factories algos))

;; test-factory : Factory (Listof Symbol) -> Void
(define (test-factory factory algos)
  (define fnv (factory-name+version factory))
  (test #:name (format "~s tests" fnv)
    (when (memq 'digest algos) (test-factory-digests factory))
    (when (memq 'cipher algos) (test-factory-ciphers factory))
    (when (memq 'pk algos) (test-factory-pks factory))
    (when (memq 'kdf algos) (test-factory-kdfs factory))))

;; xtest-factories : (Listof Factory) (Listof Symbol) -> TestSuite
(define (xtest-factories factories algos)
  (test #:name "cross"
    (when (memq 'digest algos) (xtest-digests factories))
    (when (memq 'cipher algos) (xtest-ciphers factories))
    (when (memq 'pk algos) (xtest-pks factories))
    (when (memq 'kdf algos) (xtest-kdfs factories))
    (void)))

(define (factory-name+version factory)
  (cons (send factory get-name)
        (send factory get-version)))

;; ----------------------------------------

(module+ main
  (require racket/string
           racket/cmdline
           crypto/all)
  (define algos '(digest cipher pk kdf))

  (command-line
   #:once-each
   [("--algos")
    only-algos
    "Only the given algorithm types"
    (set! algos (map string->symbol (string-split only-algos ",")))]
   #:args factories
   (let ([fnames (map string->symbol factories)])
     (define factories
       (cond [(pair? fnames)
              (filter (lambda (f) (memq (send f get-name) fnames))
                      all-factories)]
             [else all-factories]))
     (test-all factories algos))))

#;
(module+ test
  (module config info
    (define timeout 240))
  ;; disable keygen tests to avoid consuming lots of system entropy
  (test-pk-keygen? #f)
  (go))

;; TODO:
;; - add option for cross testing
;; - add option for keygen testing
;; - add option for paramgen testing (off by default?)
