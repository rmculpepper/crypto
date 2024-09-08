#lang info

;; pkg info

(define version "1.10")
(define collection "crypto")
(define deps
  '("base"
    "asn1-lib"
    ["base64-lib" #:version "1.1"]
    "binaryio-lib"
    ["gmp-lib" #:version "1.1"]
    ["scramble-lib" #:version "0.3"]))
(define pkg-authors '(ryanc))
(define license '(Apache-2.0 AND LGPL-3.0-or-later))

;; collection info

(define name "crypto")
