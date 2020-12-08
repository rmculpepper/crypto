#lang racket/base
(require racket/match
         racket/class
         racket/list
         asn1
         (only-in "cert.rkt" bytes->certificate)
         "ocsp.rkt"
         "ocsp-asn1.rkt"
         "crl.rkt"
         db/base db/sqlite3
         "interfaces.rkt")
(provide (all-defined-out))

(define-logger revocation)

(define s+ string-append)

(define schema-sqls
  (list
   ;; For untrusted tables
   (s+ "CREATE TABLE IF NOT EXISTS Cache_OCSP"
       " (url TEXT, req BLOB, basic_resp BLOB, PRIMARY KEY (url, req))")
   (s+ "CREATE TABLE IF NOT EXISTS Cache_CRL"
       " (url TEXT, crl BLOB, PRIMARY KEY (url))")
   ;; For trusted tables
   (s+ "CREATE TABLE IF NOT EXISTS Trusted_OCSP"
       " (url TEXT, certid BLOB, singleResponse BLOB, PRIMARY KEY (url, certid))")
   (s+ "CREATE TABLE IF NOT EXISTS Trusted_CRL"
       " (url TEXT, serial TEXT, status TEXT, expire INTEGER, PRIMARY KEY (url, serial))")))

;; Trusted_OCSP (ocsp-url, certid, expire, thisUpdate, nextUpdate, certStatus)

(define (make-revocation-checker db-file)
  (new revocation-checker% (db-file db-file)))

(define revocation-checker%
  (class* object% ()
    (init-field db-file)
    (super-new)

    (define conn (sqlite3-connect #:database db-file #:mode 'create))
    (define read-only? #f)
    (for ([sql (in-list schema-sqls)]) (query-exec conn sql))

    ;; ============================================================

    (define/public (check-ocsp chain [now (current-seconds)])
      (define cert (send chain get-certificate))
      (define certid-der (asn1->bytes/DER CertID (make-certid chain)))
      (define req-der (make-ocsp-request chain))
      (or (for/or ([ocsp-url (send cert get-ocsp-uris)])
            (log-revocation-debug "trying OCSP url: ~e" ocsp-url)
            (cond [(get-ocsp-single-response now chain ocsp-url certid-der req-der)
                   => (lambda (sr)
                        (match (hash-ref sr 'certStatus)
                          [(list 'good _) '()]
                          [(list 'revoked info) '(revoked)]
                          [(list 'unknown _) #f]))]
                  [else #f]))
          '(unknown)))

    ;; get-ocsp-single-response : ... -> decoded-SingleResponse or #f
    ;; The resulting SingleResponse is trusted and unexpired.
    (define/private (get-ocsp-single-response now chain ocsp-url certid-der req-der)
      (define (handle-sr sr [accept void])
        (cond [(and sr (<= now (single-response-expiration-time sr)))
               (begin (accept sr) sr)]
              [else #f]))
      (or (handle-sr (cond [(db-get-trusted-ocsp ocsp-url certid-der)
                            => (lambda (sr-der) (bytes->asn1 SingleResponse sr-der))]
                           [else #f])
                     (lambda (sr) (log-revocation-debug " using stored SingleResponse")))
          (handle-sr (cond [(get-ocsp-response now chain ocsp-url req-der)
                            => (lambda (resp) (send resp lookup-single-response
                                                    (bytes->asn1 CertID certid-der)))]
                           [else #f])
                     (lambda (sr) (db-update-trusted-ocsp now ocsp-url certid-der sr)))))

    (define/private (db-get-trusted-ocsp ocsp-url certid-der)
      (query-maybe-value conn
        "SELECT singleResponse FROM Trusted_OCSP WHERE url = ? AND certid = ?"
        ocsp-url certid-der))

    (define/private (db-update-trusted-ocsp now ocsp-url certid-der sr)
      (query-exec conn
        "INSERT OR REPLACE INTO Trusted_OCSP (url, certid, singleResponse) VALUES (?, ?, ?)"
        ocsp-url certid-der (asn1->bytes/DER SingleResponse sr)))

    ;; ----------------------------------------

    ;; get-ocsp-response : ... -> ocsp-response% or #f
    ;; The resulting response is trusted and unexpired.
    (define/public (get-ocsp-response now chain ocsp-url req-der)
      (define (handle-r whence r [accept void])
        (cond [(not r) #f]
              [(not (<= now (send r get-expiration-time)))
               (begin (log-revocation-debug " ~a ocsp expired" whence) #f)]
              [(not (send r ok-signature? (send chain get-issuer-chain-or-self)))
               (begin (log-revocation-debug " ~a ocsp bad sig" whence) #f)]
              [else (begin (accept r) r)]))

      (or (handle-r 'stored
                    (cond [(db-get-untrusted-ocsp ocsp-url req-der)
                           => (lambda (r-der) (new ocsp-response% (der r-der)))]
                          [else (begin (log-revocation-debug " no stored ocsp") #f)])
                    (lambda (r) (log-revocation-debug " using stored ocsp")))
          (handle-r 'fetched
                    (cond [(do-fetch-ocsp ocsp-url req-der)
                           => (lambda (v) (and (is-a? v ocsp-response%) v))]
                          [else #f])
                    (lambda (r) (db-update-untrusted-ocsp now ocsp-url req-der r)))))

    (define/private (db-get-untrusted-ocsp ocsp-url req-der)
      (query-maybe-value conn
        "SELECT basic_resp FROM Cache_OCSP WHERE url = ? AND req = ?"
        ocsp-url req-der))
    (define/private (db-update-untrusted-ocsp now ocsp-url req-der r)
      (when (and (not read-only?) (cachable? r))
        (query-exec conn
          "INSERT OR REPLACE INTO Cache_OCSP (url, req, basic_resp) VALUES (?, ?, ?)"
          ocsp-url req-der (send r get-der))))

    ;; ============================================================

    (define/public (check-crl chain [now (current-seconds)])
      ;; FIXME: require CRL issuer to be same as cert issuer
      (define crl-urls (certificate-crl-urls (send chain get-certificate)))
      (cond [(pair? crl-urls)
             (append*
              (for/list ([crl-url (in-list crl-urls)])
                (log-revocation-debug "trying CRL url: ~e" crl-url)
                (match (get-crl-status now chain crl-url)
                  ['absent '()]
                  ['revoked '(revoked)]
                  [#f '(unavailable)])))]
            [else '(no-crls)]))

    ;; get-crl-status : ... -> (U 'absent 'revoked #f)
    ;; If result is 'absent or 'revoked, from trusted and unexpired CRL.
    (define/private (get-crl-status now chain crl-url)
      (define cert (send chain get-certificate))
      (define serial (send cert get-serial-number))
      (define issuer-chain (send chain get-issuer-chain-or-self))
      (or (cond [(db-get-trusted-crl-status crl-url serial)
                 => (match-lambda
                      [(vector status expire)
                       (cond [(<= now expire)
                              (log-revocation-debug " using stored CRL status")
                              (string->symbol status)]
                             [else (begin (log-revocation-debug " CRL status expired") #f)])])]
                [else (begin (log-revocation-debug " no stored CRL status") #f)])
          (cond [(get-crl now crl-url issuer-chain)
                 => (lambda (crl)
                      (define revoked-serials (send crl get-revoked-serial-numbers))
                      (define status (if (member serial revoked-serials) 'revoked 'absent))
                      (define expire (send crl get-expiration-time))
                      (db-update-trusted-crl-status crl-url serial status expire)
                      status)]
                [else #f])))

    (define/private (db-get-trusted-crl-status crl-url serial)
      (query-maybe-row conn
        "SELECT status, expire FROM Trusted_CRL WHERE url = ? AND serial = ?"
        crl-url (number->string serial)))
    (define/private (db-update-trusted-crl-status crl-url serial status expire)
      (query-exec conn
        "INSERT OR REPLACE INTO Trusted_CRL (url, serial, status, expire) VALUES (?, ?, ?, ?)"
        crl-url (number->string serial) (symbol->string status) expire))

    ;; get-crl : ... -> crl% or #f
    ;; The result crl% is trusted and unexpired.
    (define/public (get-crl now crl-url issuer-chain)
      (define (handle-crl whence crl [accept void])
        (cond [(not crl) #f]
              [(not (<= now (send crl get-expiration-time)))
               (begin (log-revocation-debug " ~a CRL expired" whence) #f)]
              [(not (send crl ok-signature? issuer-chain))
               (begin (log-revocation-debug " ~a CRL bad signature" whence) #f)]
              [else (begin (log-revocation-debug " using ~a CRL" whence) (accept crl) crl)]))

      (or (handle-crl 'stored
                      (cond [(db-get-untrusted-crl crl-url)
                             => (lambda (crl-der) (new crl% (der crl-der)))]
                            [else #f]))
          (handle-crl 'fetched
                      (do-fetch-crl crl-url)
                      (lambda (crl) (db-update-untrusted-crl crl-url crl)))))

    (define/private (db-get-untrusted-crl crl-url)
      (query-maybe-value conn "SELECT crl FROM Cache_CRL WHERE url = ?" crl-url))

    (define/private (db-update-untrusted-crl crl-url crl)
      (query-exec conn
        "INSERT OR REPLACE INTO Cache_CRL (url, crl) VALUES (?, ?)"
        crl-url (send crl get-der)))
    ))

;; ============================================================

(define no-cache%
  (class* object% (cache<%>)
    (super-new)
    (define/public (fetch-ocsp ocsp-url req-der)
      (do-fetch-ocsp ocsp-url req-der))
    (define/public (fetch-crl crl-url)
      (do-fetch-crl crl-url))))
