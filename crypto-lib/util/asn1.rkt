;; Copyright 2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/contract
         (prefix-in cat: "../private/common/catalog.rkt")
         (prefix-in asn1: "../private/common/asn1.rkt"))
(provide (contract-out
          [curve-name->oid
           (-> (or/c string? symbol?)
               (or/c #f (listof exact-nonnegative-integer?)))]
          [curve-oid->name
           (-> (listof exact-nonnegative-integer?)
               (or/c #f symbol?))]
          [curve-aliases
           (-> (or/c string? symbol?)
               (listof symbol?))]))

(define (curve-name->oid alias)
  (asn1:curve-name->oid (cat:alias->curve-name alias)))

(define (curve-oid->name oid)
  (asn1:curve-oid->name oid))

(define (curve-aliases alias)
  (cat:curve-name->aliases alias))
