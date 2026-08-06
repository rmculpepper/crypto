;; Copyright 2018-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         "../common/interfaces.rkt"
         "../common/factory.rkt"
         "ffi.rkt"
         "digest.rkt")
(provide b2-factory)

(define b2-factory
  (make-factory
   #:name 'b2
   #:version '()
   #:ok? b2-ok?
   #:load-error b2-load-error
   #:get-digest b2-fetch-digest))
