;; Copyright 2020 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/contract/base
         racket/lazy-require
         "private/interfaces.rkt"
         "private/cert.rkt"
         "private/store.rkt")
(lazy-require ["private/revocation.rkt"
               (make-revocation-checker)])
(provide certificate<%>
         certificate-chain<%>
         certificate-store<%>
         certificate?
         certificate-chain?
         certificate-store?
         revocation-checker<%>
         (struct-out exn:x509)
         (struct-out exn:x509:certificate)
         (struct-out exn:x509:chain)
         x509-key-usage/c
         x509-general-name-tag/c

         (contract-out
          [bytes->certificate
           (-> bytes? certificate?)]
          [read-pem-certificates
           (->* [input-port?]
                [#:count (or/c exact-nonnegative-integer? +inf.0)
                 #:allow-aux? boolean?]
                (listof certificate?))]
          [pem-file->certificates
           (->* [path-string?]
                [#:count (or/c exact-nonnegative-integer? +inf.0)
                 #:allow-aux? boolean?]
                (listof certificate?))]
          [make-revocation-checker
           (->* [(or/c path-string? 'memory 'temporary)]
                [#:trust-db? boolean?
                 #:fetch-ocsp? boolean?
                 #:fetch-crl? boolean?]
                any)])

         empty-store
         default-store)
