#lang info

;; pkg info

(define collection "x509")
(define deps
  '("base"
    "x509-lib"))
(define build-deps
  '("rackunit-lib"
    "scribble-lib"
    "racket-doc"
    "scramble"
    "asn1-lib" "asn1-doc"
    "crypto-lib" "crypto-doc"))
(define implies '("x509-lib"))
(define pkg-authors '(ryanc))

;; collection info

(define name "x509")
(define scribblings '(("scribblings/x509.scrbl" (#;multi-page))))

(define compile-omit-paths '("examples"))
(define test-omit-paths '("examples"))
