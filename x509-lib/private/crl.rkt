#lang racket/base
(require racket/match
         racket/class
         racket/file
         racket/port
         net/url
         crypto
         asn1
         "asn1.rkt"
         (only-in "cert-data.rkt" asn1-time->seconds))
(provide (all-defined-out))

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
      (define alg (hash-ref crl 'signatureAlgorithm))
      (define alg-oid (hash-ref alg 'algorithm))
      ;; FIXME: check issuer-pk is appropriate for alg
      (unless (eq? #f (hash-ref alg 'paramters #f))
        (error 'ok-signature? "internal error: parameters not supported"))
      (define sig (match (hash-ref crl 'signature)
                    [(bit-string sig-bytes 0) sig-bytes]))
      (define di (relation-ref SIGNING 'oid alg-oid 'digest))
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
