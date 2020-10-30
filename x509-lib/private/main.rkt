#lang racket/base
(require racket/match
         racket/class
         racket/pretty
         crypto crypto/all
         "interfaces.rkt"
         "x509.rkt")

(pretty-print-columns 160)
(crypto-factories libcrypto-factory)

(define root (x509-store:openssl-trusted-directory "/etc/ssl/certs"))

;; read-chain : Path -> certificate-chain%
(define (read-chain file)
  (define certs (read-certs file))
  (match (build-chains (car certs) (cdr certs)
                       #:store (send (current-x509-store) add #:stores (list root)))
    [(cons chain _) chain]
    ['() (error 'read-chain "could not build chain")]))

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
