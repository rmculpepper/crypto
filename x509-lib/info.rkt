;; Copyright 2020 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang info

;; pkg info

(define version "1.0")
(define collection "x509")
(define deps
  '("base"
    ["asn1-lib" #:version "1.3"]
    "base64-lib"
    ["crypto-lib" #:version "1.8"]
    "db-lib"
    ["scramble-lib" #:version "0.3"]))
(define pkg-authors '(ryanc))
(define license 'Apache-2.0)

;; collection info

(define name "x509")
