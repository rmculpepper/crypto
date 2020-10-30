#lang racket/base
(require racket/match
         racket/class
         racket/pretty
         crypto crypto/all
         "interfaces.rkt"
         "validation.rkt")

(pretty-print-columns 160)
(crypto-factories libcrypto-factory)

(define root (x509-store:openssl-trusted-directory "/etc/ssl/certs"))

;; read-chain : Path -> certificate-chain%
(define (read-chain file)
  (define certs (read-certs file))
  (build-chain (car certs) (cdr certs)
               #:store (send (current-x509-store) add #:stores (list root))))

#|
Operations

build-chain : RootStore PEM [options] -> CertChain or error
POST: chain is well-formed, but not checked for any purpose
NOTE: currently policies are not implemented, ...

verify-for-purpose : CertChain Purpose -> Warnings or error
ok-for-purpose? : CertChain Purpose -> Boolean

{verify,ok}-for-{???} : CertChain
- hostname : String
- ???
|#
