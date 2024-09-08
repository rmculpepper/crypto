;; Copyright 2020 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require ffi/unsafe)
(provide (protect-out (all-defined-out)))

(define (ffi-lib-or-why-not path version)
  (with-handlers ([exn:fail? (lambda (e) (values #f (exn-message e)))])
    (values (ffi-lib path version) #f)))
