;; Copyright 2013-2022 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang info

;; pkg info

(define version "1.0")
(define collection "crypto")
(define deps '("base"))
(define build-deps '("scramble-lib"
                     "scramble"
                     "racket-doc"
                     "scribble-lib"
                     "crypto-lib"))
(define pkg-authors '(ryanc))
(define license 'Apache-2.0)

;; collection info

(define name "crypto")
(define scribblings '(("scribblings/crypto.scrbl" (multi-page))))

(define compile-omit-paths '("examples"))
(define test-omit-paths '("examples"))
