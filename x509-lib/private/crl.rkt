#lang racket/base
(require racket/match
         racket/class
         racket/file
         racket/port
         racket/list
         net/url
         crypto
         asn1
         "asn1.rkt"
         (only-in "cert.rkt" asn1-time->seconds))
(provide (all-defined-out))

;; check-not-revoked/crl : Chain -> ErrList
(define (check-not-revoked/crl chain
                               #:cache [cache the-crl-cache]
                               #:who [who 'check-not-revoked/crl])
  ;; FIXME: check all certs
  ;; FIXME: require CRL issuer to be same as cert issuer
  (define cert (send chain get-certificate))
  (define issuer (send chain get-issuer-or-self))
  (define crl-urls (certificate-crl-urls cert))
  (cond [(pair? crl-urls)
         (define serial-number (send cert get-serial-number))
         (append*
          (for/list ([crl-url (in-list crl-urls)])
            (define crl (send the-crl-cache get-crl crl-url))
            (cond [(not (send crl ok-signature? (send issuer get-public-key)))
                   '(bad-signature)]
                  ;; What to do if fetch fails or if signature fails?
                  [(member serial-number (send crl get-revoked-serial-numbers))
                   '(revoked)]
                  [else'()])))]
        [else '(no-crls)]))

(define (do-fetch-crl crl-url)
  (log-error "fetching CRL: ~e" crl-url)
  (define crl-der
    (call/input-url (string->url crl-url) get-pure-port port->bytes))
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

(define CACHE-DURATION (* 6 60 60)) ;; 6 hours

(define crl-cache%
  (class object%
    (init-field [cache-file #f])
    (super-new)

    (define crl-h (make-hash))
    (define der-h (make-hash))

    (when cache-file
      (with-handlers ([exn:fail?
                       (lambda (e)
                         (log-error "error while reading cache file: ~e" cache-file)
                         (raise e))])
        (for ([(key v) (file->value cache-file)])
          (match v
            [(cons fetched crl-der)
             (hash-set! der-h key v)
             (hash-set! crl-h key (cons fetched (new crl% (der crl-der))))]))))

    (define/private (get key)
      (hash-ref crl-h key #f))
    (define/private (put key fetched crl)
      (define crl-der (send crl get-der))
      (hash-set! crl-h key (cons fetched crl))
      (when cache-file
        (unless (equal? (cons fetched crl-der) (hash-ref der-h key #f))
          (log-error "updating CRL cache")
          (hash-set! der-h key (cons fetched crl-der))
          (call-with-output-file* cache-file #:exists 'replace
            (lambda (out) (write der-h out))))))

    (define/public (get-crl crl-url)
      (or (match (get crl-url)
            [(cons fetched crl)
             #:when (still-good? fetched crl)
             crl]
            [else #f])
          (let ([now (current-seconds)]
                [crl (do-get-crl crl-url)])
            (put crl-url now crl)
            crl)))

    (define/public (still-good? fetched crl)
      (define now (current-seconds))
      (< (current-seconds)
         (or (send crl get-next-update)
             (+ fetched CACHE-DURATION))))

    (define/private (do-get-crl crl-url)
      (log-error "fetching CRL: ~e" crl-url)
      (define crl-der
        (port->bytes (get-pure-port (string->url crl-url) #:redirections 3)))
      (define crl (new crl% (der crl-der)))
      crl)
    ))

;; Add CRL cache?
;; - use sqlite database
;; - table CRL_By_URL( url TEXT, issued TIME, nextUpdate TIME?, 

(define crl%
  (class object%
    (init-field der)
    (super-new)

    (define crl (bytes->asn1 CertificateList der))
    (define tbs (hash-ref crl 'tbsCertList))

    (define/public (get-der) der)

    ;; FIXME: well-formedness checking?

    ;; FIXME: abstract; see certificate% ok-signature?
    (define/public (ok-signature? issuer-pk)
      (define crl (bytes->asn1 CertificateList-for-verify-sig der))
      (define tbs-der (hash-ref crl 'tbsCertList))
      (define di (sig-alg->digest (hash-ref crl 'signatureAlgorithm)))
      (define sig (match (hash-ref crl 'signature)
                    [(bit-string sig-bytes 0) sig-bytes]))
      (digest/verify issuer-pk di tbs-der sig))

    (define/public (get-next-update)
      (cond [(hash-ref tbs 'nextUpdate #f) => asn1-time->seconds] [else #f]))

    (define/public (get-revoked-certificates)
      (hash-ref tbs 'revokedCertificates null))
    (define/public (get-revoked-serial-numbers)
      (map (lambda (rc) (hash-ref rc 'userCertificate))
           (get-revoked-certificates)))
    ))

(define the-crl-cache (new crl-cache%))
