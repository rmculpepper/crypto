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

;; check-not-revoked/crl : Chain -> ErrList
(define (check-not-revoked/crl chain
                               #:cache [cache #f]
                               #:who [who 'check-not-revoked/crl])
  ;; FIXME: check all certs
  ;; FIXME: require CRL issuer to be same as cert issuer
  (define cert (send chain get-certificate))
  (define issuer-chain (send chain get-issuer-chain-or-self))
  (define crl-urls (certificate-crl-urls cert))
  (cond [(pair? crl-urls)
         (define serial-number (send cert get-serial-number))
         (append*
          (for/list ([crl-url (in-list crl-urls)])
            (define crl
              (cond [cache (send cache fetch-crl crl-url)]
                    [else (do-fetch-crl crl-url)]))
            (cond [(not (send crl ok-signature? issuer-chain))
                   '(bad-signature)]
                  ;; What to do if fetch fails or if signature fails?
                  [(member serial-number (send crl get-revoked-serial-numbers))
                   '(revoked)]
                  [else '()])))]
        [else '(no-crls)]))

(define (do-fetch-crl crl-url)
  (define crl-der (call/input-url (string->url crl-url) get-pure-port port->bytes))
  (new crl% (der crl-der) (fetched-time (current-seconds))))

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
(define CRL-DEFAULT-VALIDITY-FROM-FETCHED (* 1 24 60 60)) ;; 1 day

(define crl%
  (class* object% (cachable<%>)
    (init-field der
                [fetched-time #f]) ;; only set when fetched directly from source
    (super-new)

    (define crl (bytes->asn1 CertificateList der))
    (define tbs (hash-ref crl 'tbsCertList))

    (define/public (get-der) der)
    (define/public (get-expiration-time)
      (cond [(get-next-update) => values]
            [else
             (define expire/this-update
               (+ (get-this-update) CRL-DEFAULT-VALIDITY))
             (cond [fetched-time
                    (max expire/this-update
                         (+ fetched-time CRL-DEFAULT-VALIDITY-FROM-FETCHED))]
                   [else expire/this-update])]))

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
    (define/public (get-revoked-certificates)
      (hash-ref tbs 'revokedCertificates null))
    (define/public (get-revoked-serial-numbers)
      (map (lambda (rc) (hash-ref rc 'userCertificate))
           (get-revoked-certificates)))
    ))
