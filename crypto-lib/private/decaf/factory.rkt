;; Copyright 2018-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/factory.rkt"
         "ffi.rkt"
         "digest.rkt"
         "pkey.rkt")
(provide decaf-factory)

(define (decaf-info key)
  (case key
    [(all-ec-curves) '()]
    [(all-eddsa-curves) (if decaf-is-ok? '(ed25519 ed448) '())]
    [(all-ecx-curves) (if decaf-is-ok? '(x25519 x448) '())]
    [else #f]))

(define decaf-factory
  (make-factory
   #:name 'decaf
   #:version '()
   #:ok? decaf-is-ok?
   #:load-error decaf-load-error
   #:get-digest decaf-fetch-digest
   #:get-pk decaf-fetch-pk
   #:get-info decaf-info))
