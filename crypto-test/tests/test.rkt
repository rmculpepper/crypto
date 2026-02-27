;; Copyright 2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/class
         crypto
         crypto/all
         rackunit
         rackunit/text-ui)

;; test-all : (Listof Factory) (Listof Symbol) -> Void
(define (test-all factories algos)
  (run-tests (make-all-tests factories algos)))

;; make-all-tests : (Listof Factory) (Listof Symbol) -> TestSuite
(define (make-all-tests factories algos)
  (test-suite "All tests"
    (for/list ([factory (in-list factories)])
      (make-factory-test factory algos))
    (make-cross-test factories algos)))

;; make-factory-tests : Factory (Listof Symbol) -> TestSuite
(define (make-factory-test factory algos)
  (define fnv (factory-name+version factory))
  (test-suite (format "~s tests" fnv)
    (hprintf 1 "Testing ~a\n" fnv)
    (and (memq 'digest algos) (make-factory-digest-test factory))
    (and (memq 'cipher algos) (make-factory-cipher-test factory))
    (and (memq 'pkey algos) (make-factory-pkey-test factory))
    (and (memq 'kdf algos) (make-factory-kdf-test factory))))

;; make-cross-test : (Listof Factory) (Listof Symbol) -> TestSuite
(define (make-cross-test factories algos)
  (test-suite (format "Cross tests ~s" (map (lambda (f) (send f get-name)) factories))
    ;; FIXME
    (void)))

(define (factory-name+version factory)
  (cons (send factory get-name)
        (send factory get-version)))

;; ----------------------------------------

(module+ main
  (require crypto/all)
  (define algos '(digest cipher pkey kdf))

  (command-line
   #:once-each
   [("--algos")
    only-algos
    "Only the given algorithm types"
    (set! algos (map string->symbol (string-split only-algos ",")))]
   [("--factories")
    only-factories
    "Only the given factories"
    (set! factories
          (let ([fnames (map string->symbol (string-split only-factories ","))])
            (filter (lambda (f) (memq (send f get-name) fnames))
                    factories)))]
   #:args (only-factories)
   (let ([fnames (map string->symbol (string-split only-factories ","))])
     (define factories
       (for/list ([f (in-list all-factories)]
                  #:when (memq (send f get-name) fnames))
         f))
     (do-tests factories algos))))

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
