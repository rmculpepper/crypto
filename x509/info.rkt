#lang info

;; pkg info

(define collection "x509")
(define deps '("base" "crypto-lib" "x509-lib" "crypto-doc"))
(define implies '("x509-lib"))
(define pkg-authors '(ryanc))

;; collection info

(define name "x509")
(define scribblings '(("scribblings/x509.scrbl" (multi-page))))

(define compile-omit-paths '("examples"))
(define test-omit-paths '("examples"))
