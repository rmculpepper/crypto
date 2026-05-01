;; Copyright 2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/class
         "../common/interfaces.rkt"
         "../common/factory.rkt"
         "ffi.rkt"
         "digest.rkt")
(provide b2-factory)

(define b2-factory%
  (class* factory-base% (factory<%>)
    (inherit get-cipher)
    (super-new [ok? b2-ok?] [load-error b2-load-error])

    (define/override (get-name) 'b2)
    (define/override (get-version) (and b2-ok? '()))

    (define/override (-get-digest info)
      (case (send info get-spec)
        [(blake2b blake2b-512 blake2b-384 blake2b-256 blake2b-160)
         (new b2b-digest-impl% (info info) (factory this))]
        [(blake2s blake2s-256 blake2s-224 blake2s-160 blake2s-128)
         (new b2s-digest-impl% (info info) (factory this))]
        [else #f]))
    ))

(define b2-factory (new b2-factory%))
