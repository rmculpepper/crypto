;; Copyright 2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/class
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/factory.rkt"
         "ffi.rkt"
         "digest.rkt"
         "pkey.rkt")
(provide decaf-factory)

(define decaf-factory%
  (class* factory-base% (factory<%>)
    (inherit get-cipher get-kdf)
    (inherit-field ok?)
    (super-new [ok? (decaf-is-ok?)] [load-error decaf-load-error])

    (define/override (get-name) 'decaf)
    (define/override (get-version) (and ok? '()))

    (define/override (-get-digest info)
      (case (send info get-spec)
        [(sha512)
         (new decaf-sha512-impl% (info info) (factory this))]
        [else #f]))

    (define/override (-get-pk spec)
      (case spec
        [(eddsa) (new decaf-eddsa-impl% (factory this))]
        [(ecx) (new decaf-ecx-impl% (factory this))]
        [else #f]))

    ;; ----

    (define/override (info key)
      (case key
        [(all-ec-curves) '()]
        [(all-eddsa-curves) (if ok? '(ed25519 ed448) '())]
        [(all-ecx-curves) (if ok? '(x25519 x448) '())]
        [else (super info key)]))
    ))

(define decaf-factory (new decaf-factory%))
