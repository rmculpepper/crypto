;; Copyright 2013 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang info

;; pkg info

(define version "1.10")
(define collection "crypto")
(define deps
  '("base"
    "asn1-lib"
    "hash-view-lib"
    ["base64-lib" #:version "1.1"]
    "binaryio-lib"
    ["gmp-lib" #:version "1.1"]
    ["scramble-lib" #:version "0.3"]))
(define pkg-authors '(ryanc))
(define license 'Apache-2.0)

;; collection info

(define name "crypto")
