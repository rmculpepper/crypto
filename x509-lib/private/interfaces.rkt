#lang racket/base
(require racket/contract
         racket/class)
(provide (all-defined-out))

(define (certificate? v) (is-a? v -certificate<%>))
(define (certificate-chain? v) (is-a? v -certificate-chain<%>))
(define (certificate-store? v) (is-a? v -certificate-store<%>))

(define certificate-data<%>
  (interface ()
   has-same-public-key?

   get-der
   get-cert-signature-info

   get-version
   get-serial-number
   get-issuer
   get-validity
   get-subject
   get-spki
   get-issuer-unique-id
   get-subject-unique-id
   get-extensions
   get-subject-common-names

   is-CA?
   is-self-issued?
   is-self-signed?
   get-key-uses
   ok-key-use?
   get-eku
   get-ekus

   get-extension
   get-extension-value

   get-name-constraints
   get-subject-alt-names
   get-validity-seconds
   ))

(define certificate<%>
  (interface (certificate-data<%> equal<%> writable<%>)
    ))

(define time/c exact-integer?)
(define candidate-chain/c (non-empty-listof certificate?))

(define certificate-chain<%>
  (interface ()
    get-certificate
    get-issuer-chain
    get-anchor
    is-anchor?

    get-subject
    get-subject-alt-names
    ok-key-use?
    ok-extended-key-usage?

    get-public-key
    check-signature

    [trusted?
     (->*m [(or/c #f certificate-store?)] [time/c time/c]
           boolean?)]
    ))

;; Note: for documentation; not actually implemented
(define trust-anchor<%>
  (interface ()
    get-public-key
    get-subject
    ))

(define Name/c any/c) ;; FIXME: contract from asn1?

(define x509-lookup<%>
  (interface ()
    [trust?            (->m certificate? boolean?)]
    [lookup-by-subject (->m Name/c (listof certificate?))]
    ))

(define certificate-store<%>
  (interface (x509-lookup<%>)
    [add
     (->*m []
           [#:trusted-certs (listof certificate?)
            #:untrusted-certs (listof certificate?)
            #:set-security-level (or/c 0 1 2 3 4 5)]
           certificate-store?)]
    [add-trusted-from-pem-file
     (->m path-string? certificate-store?)]
    [add-trusted-from-openssl-directory
     (->m path-string? certificate-store?)]

    [build-chain
     (->*m [certificate?]
           [(listof certificate?)
            time/c]
           certificate-chain?)]
    [build-chains
     (->*m [certificate?] [(listof certificate?) time/c #:empty-ok? boolean?]
           (listof certificate-chain?))]
    [pem-file->chain
     (->*m [path-string?] [time/c]
           certificate-chain?)]
    ))

(define -certificate<%>
  (interface (certificate<%>)))
(define -certificate-chain<%>
  (interface (certificate-chain<%>)))
(define -certificate-store<%>
  (interface (certificate-store<%>)
    [build-candidate-chains
     (->m certificate?
          (listof candidate-chain/c))]
    [check-chain
     (->*m [candidate-chain/c] [time/c]
           certificate-chain?)]
    [check-chains
     (->*m [(listof candidate-chain/c)] [time/c #:empty-ok? boolean?]
           (listof certificate-chain?))]
    ))

(struct exn:x509 exn:fail () #:transparent)
(struct exn:x509:certificate exn:x509 (errors) #:transparent)
(struct exn:x509:chain exn:x509 (errors) #:transparent)

;; An ErrorList is a list of "error description" values.
;; The empty list means no errors were detected.

(define-logger x509)

(define cache<%>
  (interface ()
    fetch-ocsp ;; URL OCSPRequest -> ocsp-response%
    fetch-crl  ;; URL -> crl%
    ))

(define cachable<%>
  (interface ()
    get-expiration-time ;; Seconds
    get-der ;; -> Bytes
    ))

(define (cachable? v) (is-a? v cachable<%>))
