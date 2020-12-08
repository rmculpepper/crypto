#lang racket/base
(require racket/match
         racket/class
         racket/file
         racket/port
         racket/list
         net/url
         asn1
         "interfaces.rkt"
         "asn1.rkt"
         (only-in "cert.rkt" asn1-time->seconds))
(provide (all-defined-out))

(define (do-fetch-crl crl-url)
  (define crl-der (call/input-url (string->url crl-url) get-pure-port port->bytes))
  (new crl% (der crl-der)))

(define (certificate-crl-urls cert)
  (define crl-dists (send cert get-crl-distribution-points))
  (flatten
   (for/list ([crl-dist (in-list crl-dists)]
              ;; FIXME: we only handle case where CRL issuer is same as cert issuer
              #:when (not (hash-has-key? crl-dist 'cRLIssuer)))
     (match (hash-ref crl-dist 'distributionPoint #f)
       [(list 'fullName gnames)
        (for/list ([gname (in-list gnames)])
          (match gname
            [(list 'uniformResourceIdentifier
                   (and (regexp #rx"^(?i:https?)://") url))
             (list url)]
            [_ null]))]
       [_ null]))))

;; ----------------------------------------

(define CRL-DEFAULT-VALIDITY (* 7 24 60 60)) ;; 1 week

(define crl%
  (class* object% (cachable<%>)
    (init-field der)
    (super-new)

    (define crl (bytes->asn1 CertificateList der))
    (define tbs (hash-ref crl 'tbsCertList))

    (define/public (get-der) der)
    (define/public (get-expiration-time)
      (cond [(get-next-update) => values]
            [else (+ (get-this-update) CRL-DEFAULT-VALIDITY)]))

    ;; FIXME: well-formedness checking?

    (define/public (ok-signature? issuer-chain)
      (define crl (bytes->asn1 CertificateList-for-verify-sig der))
      (define tbs-der (hash-ref crl 'tbsCertList))
      (define algid (hash-ref crl 'signatureAlgorithm))
      (define sig (match (hash-ref crl 'signature)
                    [(bit-string sig-bytes 0) sig-bytes]))
      (null? (send issuer-chain check-signature algid tbs-der sig)))

    (define/public (get-this-update)
      (asn1-time->seconds (hash-ref tbs 'thisUpdate)))
    (define/public (get-next-update)
      (cond [(hash-ref tbs 'nextUpdate #f) => asn1-time->seconds] [else #f]))
    (define/public (revoked? serial)
      (for/or ([rc (in-list (hash-ref tbs 'revokedCertificates null))])
        (equal? serial (hash-ref rc 'userCertificate))))
    ))
