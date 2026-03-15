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
  (run-tests (lambda () (do-all-tests factories algos))
             #:progress? #t))

;; do-all-tests : (Listof Factory) (Listof Symbol) -> Void
(define (do-all-tests factories algos)
  (for ([factory (in-list factories)])
    (do-factory-test factory algos))
  (do-cross-test factories algos))

;; do-factory-tests : Factory (Listof Symbol) -> Void
(define (do-factory-test factory algos)
  (define fnv (factory-name+version factory))
  (test #:name (format "~s tests" fnv)
    (when (memq 'digest algos) (test-factory-digests factory))
    (when (memq 'cipher algos) (test-factory-ciphers factory))
    (when (memq 'pkey algos) (test-factory-pkeys factory))
    (when (memq 'kdf algos) (test-factory-kdfs factory))))

;; do-cross-test : (Listof Factory) (Listof Symbol) -> TestSuite
(define (do-cross-test factories algos)
  (test #:name (format "cross tests ~s" (map factory-name+version factories))
    ;; FIXME
    (void)))

(define (factory-name+version factory)
  (cons (send factory get-name)
        (send factory get-version)))

;; ----------------------------------------

(module+ main
  (require racket/string
           racket/cmdline
           crypto/all)
  (define algos '(digest cipher pkey kdf))

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
