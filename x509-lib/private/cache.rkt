#lang racket/base
(require racket/match
         racket/class
         (only-in "cert.rkt" bytes->certificate)
         (only-in "ocsp.rkt" ocsp-response% do-fetch-ocsp)
         (only-in "crl.rkt" crl% do-fetch-crl)
         db/base db/sqlite3
         "interfaces.rkt")
(provide (all-defined-out)
         no-cache)

(define no-cache%
  (class* object% (cache<%>)
    (super-new)
    (define/public (make-certificate der) (bytes->certificate der))
    (define/public (fetch-ocsp ocsp-url req-der)
      (do-fetch-ocsp ocsp-url req-der))
    (define/public (fetch-crl crl-url)
      (do-fetch-crl crl-url))))

(define no-cache (new no-cache%))

(define db-cache%
  (class* object% (cache<%>)
    (init-field parent db-file
                [read-only? #f])
    (super-new)

    (define conn (sqlite3-connect #:database db-file #:mode 'create))
    (query-exec conn
      "CREATE TABLE IF NOT EXISTS Cache_OCSP (url TEXT, req BLOB, expire INTEGER, basic_resp BLOB)")
    (query-exec conn
      "CREATE TABLE IF NOT EXISTS Cache_CRL (url TEXT, expire INTEGER, crl BLOB)")

    (define/public (make-certificate der)
      (send parent make-certificate der))

    (define/public (fetch-ocsp ocsp-url req-der)
      (define now (current-seconds))
      (define r-der
        (query-maybe-value conn
          "SELECT basic_resp FROM Cache_OCSP WHERE url = ? AND req = ? ORDER BY expire DESC LIMIT 1"
          ocsp-url req-der))
      (define r (and r-der (new ocsp-response% (der r-der))))
      (eprintf "fetch-ocsp: db has ~e\n" r)
      (cond [(and r (< now (send r get-expiration-time))) r]
            [else
             (eprintf "db-cache: fault for ~e\n" ocsp-url)
             (define r (send parent fetch-ocsp ocsp-url req-der))
             (when (and (not read-only?) (cachable? r))
               (query-exec conn
                 "DELETE FROM Cache_OCSP WHERE expire < ?" now)
               (query-exec conn
                 "INSERT INTO Cache_OCSP (url, req, expire, basic_resp) VALUES (?, ?, ?, ?)"
                 ocsp-url req-der (send r get-expiration-time) (send r get-der)))
             r]))

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

    ;; cert-h : Hash[Bytes => Certificate]
    (define cert-h (make-weak-hash))

    (define/public (make-certificate der)
      (hash-ref! cert-h der (lambda () (send parent make-certificate der))))

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
  (define cache1 (if db-file (new db-cache% (db-file db-file) (parent no-cache)) no-cache))
  (new mem-cache% (parent cache1)))
