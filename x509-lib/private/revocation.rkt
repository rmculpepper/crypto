#lang racket/base
(require racket/match
         racket/class
         racket/list
         racket/port
         scramble/result
         net/url
         net/uri-codec
         db/base
         db/sqlite3
         asn1
         asn1/util/time
         base64
         (only-in crypto/private/common/asn1 id-sha1)
         (only-in "cert.rkt" bytes->certificate Name-equal? asn1-time->seconds)
         (only-in "asn1.rkt" Name CertificateList CertificateList-for-verify-sig)
         (only-in "ocsp-asn1.rkt" OCSPRequest CertID id-pkix-ocsp-basic
                  OCSPResponse ResponseData SingleResponse BasicOCSPResponse)
         "interfaces.rkt"
         "util.rkt")
(provide (all-defined-out))

(define-logger revocation)

(define DEFAULT-VALID-TIME (* 7 24 60 60))

;; ============================================================

(define (make-revocation-checker db-file
                                 #:trust-db? [trust-db? #t]
                                 #:fetch-ocsp? [fetch-ocsp? #t]
                                 #:fetch-crl? [fetch-crl? #t])
  (new revocation-checker% (db-file db-file) (trust-db? trust-db?)
       (fetch-ocsp? fetch-ocsp?) (fetch-crl? fetch-crl?)))

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

(define revocation-checker%
  (class* object% ()
    (init-field db-file
                [trust-db? #t]
                [fetch-ocsp? #t]
                [fetch-crl? #t])
    (super-new)

    (define conn (sqlite3-connect #:database db-file #:mode 'create))
    (define read-only? #f)
    (for ([sql (in-list schema-sqls)]) (query-exec conn sql))

    ;; ============================================================

    ;; check-ocsp : Chain Seconds -> (Result #t Symbol)
    (define/public (check-ocsp chain [now (current-seconds)])
      (define cert (send chain get-certificate))
      (define certid-der (asn1->bytes/DER CertID (make-certid chain)))
      (define req-der (make-ocsp-request chain))
      (define ocsp-urls (send cert get-ocsp-uris))
      (cond [(pair? ocsp-urls)
             (or (for/or ([ocsp-url (in-list ocsp-urls)])
                   (log-revocation-debug "trying OCSP url: ~e" ocsp-url)
                   (cond [(get-ocsp-single-response now chain ocsp-url certid-der req-der)
                          => (lambda (sr)
                               (match (hash-ref sr 'certStatus)
                                 [(list 'good _) (ok #t)]
                                 [(list 'revoked info) (bad 'revoked)]
                                 [(list 'unknown _) #f]))]
                         [else #f]))
                 (bad 'unknown))]
            [else (bad 'no-sources)]))

    ;; get-ocsp-single-response : ... -> decoded-SingleResponse or #f
    ;; The resulting SingleResponse is trusted and unexpired.
    (define/private (get-ocsp-single-response now chain ocsp-url certid-der req-der)
      (define (handle-sr sr [accept void])
        (cond [(and sr (single-response-valid-now? sr now))
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
      (and trust-db?
           (query-maybe-value conn
             "SELECT singleResponse FROM Trusted_OCSP WHERE url = ? AND certid = ?"
             ocsp-url certid-der)))

    (define/private (db-update-trusted-ocsp now ocsp-url certid-der sr)
      (when trust-db?
        (query-exec conn
          "INSERT OR REPLACE INTO Trusted_OCSP (url, certid, singleResponse) VALUES (?, ?, ?)"
          ocsp-url certid-der (asn1->bytes/DER SingleResponse sr))))

    ;; ----------------------------------------

    ;; get-ocsp-response : ... -> ocsp-response% or #f
    ;; The resulting response is trusted and unexpired.
    (define/public (get-ocsp-response now chain ocsp-url req-der)
      (define (handle-r whence r [accept void])
        (cond [(not r) #f]
              [(not (send r valid-now? now))
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
                    (cond [(and fetch-ocsp? (do-fetch-ocsp ocsp-url req-der))
                           => (lambda (v) (and (is-a? v ocsp-response%) v))]
                          [else #f])
                    (lambda (r) (db-update-untrusted-ocsp now ocsp-url req-der r)))))

    (define/private (db-get-untrusted-ocsp ocsp-url req-der)
      (query-maybe-value conn
        "SELECT basic_resp FROM Cache_OCSP WHERE url = ? AND req = ?"
        ocsp-url req-der))
    (define/private (db-update-untrusted-ocsp now ocsp-url req-der r)
      (query-exec conn
        "INSERT OR REPLACE INTO Cache_OCSP (url, req, basic_resp) VALUES (?, ?, ?)"
        ocsp-url req-der (send r get-der)))

    ;; ============================================================

    ;; check-crl : Chain Seconds -> (Result #t Symbol)
    (define/public (check-crl chain [now (current-seconds)])
      ;; FIXME: require CRL issuer to be same as cert issuer
      (define crl-urls (certificate-crl-urls (send chain get-certificate)))
      (cond [(pair? crl-urls)
             (define responses
               (for/list ([crl-url (in-list crl-urls)])
                 (log-revocation-debug "trying CRL url: ~e" crl-url)
                 (or (get-crl-status now chain crl-url) 'unavailable)))
             (cond [(memq 'revoked responses) (bad 'revoked)]
                   [(memq 'unavailable responses) (bad 'unknown)]
                   [(andmap (lambda (resp) (eq? resp 'absent)) responses) (ok #t)]
                   [else (bad 'unknown)])]
            [else (bad 'no-sources)]))

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
                      (define status (if (send crl revoked? serial) 'revoked 'absent))
                      (define expire (send crl get-expiration-time))
                      (db-update-trusted-crl-status crl-url serial status expire)
                      status)]
                [else #f])))

    (define/private (db-get-trusted-crl-status crl-url serial)
      (and trust-db?
           (query-maybe-row conn
             "SELECT status, expire FROM Trusted_CRL WHERE url = ? AND serial = ?"
             crl-url (number->string serial))))
    (define/private (db-update-trusted-crl-status crl-url serial status expire)
      (when trust-db?
        (query-exec conn
          "INSERT OR REPLACE INTO Trusted_CRL (url, serial, status, expire) VALUES (?, ?, ?, ?)"
          crl-url (number->string serial) (symbol->string status) expire)))

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
                      (and fetch-crl? (do-fetch-crl crl-url))
                      (lambda (crl) (db-update-untrusted-crl crl-url crl)))))

    (define/private (db-get-untrusted-crl crl-url)
      (query-maybe-value conn "SELECT crl FROM Cache_CRL WHERE url = ?" crl-url))

    (define/private (db-update-untrusted-crl crl-url crl)
      (query-exec conn
        "INSERT OR REPLACE INTO Cache_CRL (url, crl) VALUES (?, ?)"
        crl-url (send crl get-der)))
    ))

;; ============================================================
;; OCSP

;; It seems that OCSP responders are very fragile and finicky.
;; - Might respond "malformed" if request does not use sha1 for CertID hash.
;; - Might respond only to first certificate in request. (Probably to enable
;;   static responses.)
;; - Might not support GET request.
;; So: use sha1, limit request to single certificate.

;; Discussion about sha1 as CertID hash algorithm:
;; - (2019) https://groups.google.com/g/mozilla.dev.security.policy/c/ImCmDRMj-JU

(define (do-fetch-ocsp ocsp-url req-der)
  (let loop ([try-get? #t])
    (define headers '("Content-Type: application/ocsp-request"))
    (define req-b64-url
      (and try-get?
           (let* ([req-b64 (uri-encode (bytes->string/utf-8 (base64-encode req-der)))]
                  [req-url (string->url (string-append ocsp-url "/" req-b64))])
             (and (<= (string-length (url->string req-url)) 255)
                  req-url))))
    (define resp-in
      (cond [req-b64-url => (lambda (req-url) (get-impure-port req-url headers))]
            [else (post-impure-port (string->url ocsp-url) req-der headers)]))
    (define header (purify-port resp-in))
    (define resp-bytes (port->bytes resp-in))
    (close-input-port resp-in)
    (cond [(regexp-match? #rx"^HTTP/[0-9.]* 200" header)
           (parse-ocsp-response resp-bytes)]
          [req-b64-url (loop #f)]
          [else 'failed-to-fetch])))

(define SubjectPublicKeyInfo-shallow
  (SEQUENCE [algorithm ANY] [subjectPublicKey BIT-STRING]))

(define (certificate-keyhash cert)
  (define spki (bytes->asn1 SubjectPublicKeyInfo-shallow (send cert get-spki)))
  (define pk (bit-string-bytes (hash-ref spki 'subjectPublicKey)))
  (sha1-bytes pk))

;; Note: Use no-params version of certID for all db keys, regardless
;; of responder certID format.
(define (make-certid chain)
  (define cert (send chain get-certificate))
  (define issuer (send chain get-issuer-or-self))
  (hasheq 'hashAlgorithm (hasheq 'algorithm id-sha1) ;; no params
          'issuerNameHash (sha1-bytes (asn1->bytes/DER Name (send issuer get-subject)))
          'issuerKeyHash (certificate-keyhash issuer)
          'serialNumber (send cert get-serial-number)))

(define (certid=? a b)
  ;; Avoid comparing hashAlgorithm, parameter presence varies.
  (for/and ([key (in-list '(issuerNameHash issuerKeyHash serialNumber))])
    (equal? (hash-ref a key) (hash-ref b key))))

(define (make-ocsp-request chain)
  (define cert (send chain get-certificate))
  (define issuer (send chain get-issuer-or-self))
  (define certid (make-certid chain))
  (define reqlist (list (hasheq 'reqCert certid)))
  (define tbs (hasheq 'requestList reqlist))
  (define req (hasheq 'tbsRequest tbs))
  (asn1->bytes/DER OCSPRequest req))

;; parse-ocsp-response : Bytes -> ocsp-response% or Symbol
(define (parse-ocsp-response der)
  (define resp (bytes->asn1 OCSPResponse der))
  (define rb (hash-ref resp 'responseBytes #f))
  (define rtype (and rb (hash-ref rb 'responseType)))
  (define rbody (and rb (hash-ref rb 'response)))
  (if (and (equal? rtype id-pkix-ocsp-basic) rbody)
      (new ocsp-response% (rbody rbody))
      (hash-ref resp 'responseStatus)))

(define ocsp-response%
  (class* object% (cachable<%>)
    (init-field [der #f]
                [rbody (bytes->asn1 BasicOCSPResponse der)])
    (super-new)

    (define rdata (hash-ref rbody 'tbsResponseData))
    (unless der (set! der (asn1->bytes/DER BasicOCSPResponse rbody)))

    (define/public (get-der) der)
    (define/public (get-response-data) rdata)
    (define/public (get-responder-id) (hash-ref rdata 'responderID))
    (define/public (get-produced-at) (hash-ref rdata 'producedAt))
    (define/public (get-responses) (hash-ref rdata 'responses))
    ;; FIXME: process extensions

    (define/public (valid-now? now)
      (for/and ([sr (in-list (get-responses))])
        (single-response-valid-now? sr now)))

    (define/public (get-expiration-time)
      (apply min (map single-response-expiration-time (get-responses))))

    ;; Verify signature
    (define/public (ok-signature? issuer-chain)
      (define tbs-der (asn1->bytes/DER ResponseData rdata))
      (define algid (hash-ref rbody 'signatureAlgorithm))
      (define sig (match (hash-ref rbody 'signature)
                    [(bit-string sig-bytes 0) sig-bytes]))
      (define responder-chain (get-responder-chain issuer-chain))
      (and responder-chain
           (ok? (send responder-chain check-signature algid tbs-der sig))))

    (define/public (get-responder-chain issuer-chain)
      (define (is-responder? cert)
        (match (get-responder-id)
          [(list 'byName responder-name)
           (Name-equal? responder-name (send cert get-subject))]
          [(list 'byKey keyhash)
           (equal? keyhash (certificate-keyhash cert))]))
      (cond [(is-responder? (send issuer-chain get-certificate)) issuer-chain]
            [else
             (define certs (map bytes->certificate (hash-ref rbody 'certs null)))
             (for/or ([cert (in-list certs)])
               (and (is-responder? cert)
                    (let ([chain (send issuer-chain extend-chain cert)])
                      (and (certificate-chain? chain)
                           (send chain suitable-for-ocsp-signing? issuer-chain)
                           ;; We omit the store trust check because issuer-chain
                           ;; has (presumably) already been checked for trust, and
                           ;; the new chain has the same trust anchor.
                           (send chain trusted? #f)
                           chain))))]))

    (define/public (lookup-single-response certid)
      (match (lookup-single-responses certid)
        [(cons sr more)
         (when (pair? more)
           (log-revocation-error "multiple matching OCSP SingleResponses"))
         sr]
        [(list) #f]))

    (define/public (lookup-single-responses certid)
      (for/list ([sr (in-list (get-responses))]
                  #:when (certid=? (hash-ref sr 'certID) certid))
        sr))
    ))

(define (single-response-valid-now? sr now)
  ;; RFC 5019 says must reject if nextUpdate is absent.
  (define nextUpdate (hash-ref sr 'nextUpdate #f))
  (and nextUpdate
       (<= (asn1-generalized-time->seconds (hash-ref sr 'thisUpdate))
           now
           (asn1-generalized-time->seconds nextUpdate))))

(define (single-response-expiration-time sr)
  (cond [(hash-ref sr 'nextUpdate #f) => asn1-generalized-time->seconds]
        [else #| treat it like past |# 0]))

;; ============================================================
;; CRL

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

(define crl%
  (class* object% (cachable<%>)
    (init-field der)
    (super-new)

    (define crl (bytes->asn1 CertificateList der))
    (define tbs (hash-ref crl 'tbsCertList))

    (define/public (get-der) der)
    (define/public (get-expiration-time)
      (cond [(get-next-update) => values]
            [else (+ (get-this-update) DEFAULT-VALID-TIME)]))

    ;; FIXME: well-formedness checking?

    (define/public (ok-signature? issuer-chain)
      (define crl (bytes->asn1 CertificateList-for-verify-sig der))
      (define tbs-der (hash-ref crl 'tbsCertList))
      (define algid (hash-ref crl 'signatureAlgorithm))
      (define sig (match (hash-ref crl 'signature)
                    [(bit-string sig-bytes 0) sig-bytes]))
      (ok? (send issuer-chain check-signature algid tbs-der sig)))

    (define/public (get-this-update)
      (asn1-time->seconds (hash-ref tbs 'thisUpdate)))
    (define/public (get-next-update)
      (cond [(hash-ref tbs 'nextUpdate #f) => asn1-time->seconds] [else #f]))
    (define/public (revoked? serial)
      (for/or ([rc (in-list (hash-ref tbs 'revokedCertificates null))])
        (equal? serial (hash-ref rc 'userCertificate))))
    ))
