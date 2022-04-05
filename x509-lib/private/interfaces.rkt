#lang racket/base
(require racket/contract
         racket/class
         (only-in asn1 asn1-oid? bit-string?)
         (only-in crypto crypto-factory? public-only-key?))
(provide (all-defined-out))

(define (certificate? v) (is-a? v -certificate<%>))
(define (certificate-chain? v) (is-a? v -certificate-chain<%>))
(define (certificate-store? v) (is-a? v -certificate-store<%>))

(define asn1-algorithm-identifier/c (flat-named-contract 'asn1-algorithm-identifier/c hash?))
(define x509-extension/c (flat-named-contract 'x509-extension/c hash?))
(define x509-name/c (flat-named-contract 'x509-name/c any/c))
(define x509-name-constraints/c (flat-named-contract 'x509-name-constraints/c hash?))
(define x509-validity/c (flat-named-contract 'x509-validity/c hash?))

(define x509-key-usage/c
  (or/c 'digitalSignature 'nonRepudiation 'keyEncipherment 'dataEncipherment
        'keyAgreement 'keyCertSign 'cRLSign 'encipherOnly 'decipherOnly))

(define x509-general-name-tag/c
  (or/c 'otherName 'rfc822Name 'dNSName 'x400Address 'directoryName
        'ediPartyName 'uniformResourceIdentifier 'iPAddress 'registeredID))

(define x509-general-name/c
  (or/c (list/c 'otherName any/c)
        (list/c 'rfc822Name string?)
        (list/c 'dNSName string?)
        (list/c 'x400Address any/c)
        (list/c 'directoryName x509-name/c)
        (list/c 'ediPartyName any/c)
        (list/c 'uniformResourceIdentifier string?)
        (list/c 'iPAddress bytes?)
        (list/c 'registeredID asn1-oid?)))

(define certificate-data<%>
  (interface ()
    [has-same-public-key? (->m certificate? boolean?)]

    [get-der (->m bytes?)]
    [get-cert-signature-info (->m (values asn1-algorithm-identifier/c bytes? bytes?))]

    [get-version (->m exact-integer?)] ;; Note: 2 represents v3
    [get-serial-number (->m exact-integer?)]
    [get-issuer (->m x509-name/c)]
    [get-validity (->m x509-validity/c)]
    [get-subject (->m x509-name/c)]
    [get-spki (->m bytes?)]
    [get-issuer-unique-id (->m (or/c #f bit-string?))]
    [get-subject-unique-id (->m (or/c #f bit-string?))]
    [get-extensions (->m (listof x509-extension/c))]
    [get-subject-common-names (->m (listof string?))]

    [is-CA? (->m boolean?)]
    [is-self-issued? (->m boolean?)]
    [is-self-signed? (->m boolean?)] ;; FIXME: remove?
    [get-key-usages (case->m (-> (listof x509-key-usage/c))
                             (-> any/c any/c))]
    [ok-key-usage? (->*m [x509-key-usage/c] [any/c] any)]
    [get-extended-key-usage (->m asn1-oid? (or/c 'yes 'no 'unset))]
    [get-extended-key-usages (case->m (-> (listof asn1-oid?))
                                      (-> any/c any/c))]

    [get-extension (->m asn1-oid? (or/c #f x509-extension/c))]
    [get-extension-value (->m asn1-oid? any/c any)]

    [get-name-constraints (->m (or/c #f x509-name-constraints/c))]
    [get-subject-alt-names
     (case->m (-> (listof x509-general-name/c))
              (-> (or/c #f x509-general-name-tag/c)
                  (or/c (listof string?) (listof x509-general-name/c))))]
    [get-validity-seconds (->m (list/c exact-integer? exact-integer?))]
    ))

(define certificate<%>
  (interface (certificate-data<%> equal<%> writable<%>)
    ))

(define time/c exact-integer?)
(define candidate-chain/c (non-empty-listof certificate?))

(define certificate-chain<%>
  (interface ()
    [get-certificate (->m certificate?)]
    [get-issuer-chain (->m (or/c #f certificate-chain?))]
    [get-anchor (->m certificate?)]
    [is-anchor? (->m boolean?)]

    [get-subject (->m x509-name/c)]
    [get-subject-alt-names
     (case->m (-> (listof x509-general-name/c))
              (-> (or/c #f x509-general-name-tag/c)
                  (or/c (listof string?) (listof x509-general-name/c))))]
    [ok-key-usage? (->*m [x509-key-usage/c] [any/c] any)]
    [ok-extended-key-usage? (->*m [asn1-oid?] [any/c] any)]

    [get-public-key
     (->*m [] [(or/c crypto-factory? (listof crypto-factory?))] public-only-key?)]
    [check-signature (->m asn1-algorithm-identifier/c bytes? bytes? list?)] ;; FIXME ?

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

(define x509-lookup<%>
  (interface ()
    [trust?            (->m certificate? boolean?)]
    [lookup-by-subject (->m x509-name/c (listof certificate?))]
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

(define revocation-checker<%>
  (interface ()
    [check-ocsp (->m certificate-chain? list?)]
    [check-crl (->m certificate-chain? list?)]
    ))

(define cachable<%>
  (interface ()
    [get-expiration-time (->m rational?)] ;; Seconds
    [get-der (->m bytes?)]
    ))
