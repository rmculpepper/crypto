#lang racket/base
(require racket/match
         racket/class
         asn1
         (only-in "cert.rkt" bytes->certificate)
         "ocsp.rkt"
         "ocsp-asn1.rkt"
         (only-in "crl.rkt" crl% do-fetch-crl)
         db/base db/sqlite3
         "interfaces.rkt")
(provide (all-defined-out)
         no-cache)

(define-logger revocation)

(define s+ string-append)

(define schema-sqls
  (list
   ;; For untrusted tables
   (s+ "CREATE TABLE IF NOT EXISTS Cache_OCSP"
       " (url TEXT, req BLOB, basic_resp BLOB, PRIMARY KEY (url, req))")
   (s+ "CREATE TABLE IF NOT EXISTS Cache_CRL"
       " (url TEXT, expire INTEGER, crl BLOB, PRIMARY KEY (url))")
   ;; For trusted tables
   (s+ "CREATE TABLE IF NOT EXISTS Trusted_OCSP"
       " (url TEXT, certid BLOB, singleResponse BLOB, PRIMARY KEY (url, certid))")))

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
      (or (for/or ([ocsp-url (send cert get-ocsp-urls)])
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
                           [else #f]))
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
               (begin (log-revocation-debug "~a ocsp expired for ~e" whence ocsp-url) #f)]
              [(not (send r ok-signature? (send chain get-issuer-chain-or-self)))
               (begin (log-revocation-debug "~a ocsp bad sig for ~e" whence ocsp-url) #f)]
              [else (begin (accept r) r)]))

      (or (handle-r 'stored
                    (cond [(db-get-untrusted-ocsp ocsp-url req-der)
                           => (lambda (r-der) (new ocsp-response% (der r-der)))]
                          [else (log-revocation-debug "no stored ocsp for ~e" ocsp-url) #f]))
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
    ))

(define no-cache%
  (class* object% (cache<%>)
    (super-new)
    (define/public (fetch-ocsp ocsp-url req-der)
      (do-fetch-ocsp ocsp-url req-der))
    (define/public (fetch-crl crl-url)
      (do-fetch-crl crl-url))))

(define no-cache (new no-cache%))

(define db-cache%
  (class* object% (cache<%>)
    (init-field parent conn
                [read-only? #f])
    (super-new)

    (define/public (fetch-crl crl-url)
      (define now (current-seconds))
      (define r-der
        (query-maybe-value conn
          "SELECT crl FROM Cache_CRL WHERE url = ? ORDER BY expire DESC LIMIT 1"
          crl-url))
      (define r (and r-der (new crl% (der r-der))))
      (cond [(and r (< now (send r get-expiration-time))) r]
            [else
             (eprintf "db-cache: fault for ~e\n" crl-url)
             (define r (send parent fetch-crl crl-url))
             (when (and (not read-only?) (cachable? r))
               (query-exec conn
                 "DELETE FROM Cache_CRL WHERE expire < ?" now)
               (query-exec conn
                 "INSERT INTO Cache_CRL (url, expire, crl) VALUES (?, ?, ?)"
                 crl-url (send r get-expiration-time) (send r get-der)))
             r]))
    ))

(define mem-cache%
  (class* object% (cache<%>)
    (init-field parent)
    (super-new)

    (define/private (get! cache-h key fault)
      (define r (hash-ref cache-h key #f))
      (define now (current-seconds))
      (if (and r (< now (send r get-expiration-time)))
          r
          (let ([r (fault)])
            (eprintf "mem-cache: fault for ~e\n" key)
            (when (cachable? r) (hash-set! cache-h key r))
            r)))

    ;; ocsp-h : Hash[(cons String[URL] Bytes[Req-DER]) => ocsp-response%]
    (define ocsp-h (make-hash))

    (define/public (fetch-ocsp ocsp-url req)
      (get! ocsp-h (cons ocsp-url req)
            (lambda () (send parent fetch-ocsp ocsp-url req))))

    ;; crl-h : Hash[String[URL] => crl%]
    (define crl-h (make-hash))

    (define/public (fetch-crl crl-url)
      (get! crl-h crl-url
            (lambda () (send parent fetch-crl crl-url))))
    ))

(define (make-cache [db-file #f])
  (define conn (and db-file (sqlite3-connect #:database db-file #:mode 'create)))
  (define cache1 (if conn (new db-cache% (conn conn) (parent no-cache)) no-cache))
  (new mem-cache% (parent cache1)))
