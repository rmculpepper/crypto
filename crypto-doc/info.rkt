#lang info

;; pkg info

(define version "1.0")
(define collection "crypto")
(define deps '("base"))
(define build-deps '("racket-doc"
                     "scribble-lib"
                     "crypto-lib"))
(define pkg-authors '(ryanc))

;; collection info

(define name "crypto")
(define scribblings '(("scribblings/crypto.scrbl" (multi-page))))

(define test-omit-paths '("examples"))
