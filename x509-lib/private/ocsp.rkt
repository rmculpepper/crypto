#lang racket/base
(require racket/match
         racket/class
         racket/port
         net/url
         base64
         asn1
         asn1/util/time
         (only-in "asn1.rkt" Name)
         (submod "asn1.rkt" verify)
         (only-in "cert.rkt" Name-equal? bytes->certificate)
         "interfaces.rkt"
         "ocsp-asn1.rkt")
(provide (all-defined-out))

;; It seems that OCSP responders are very fragile and finicky.
;; - Might respond "malformed" if request does not use sha1.
;; - Might respond only to first certificate in request. (Probably to enable
;;   static responses.)
;; - Might not support GET request.
;; So: use sha1, limit request to single certificate.

(define (do-fetch-ocsp ocsp-url req-der)
  (let loop ([try-get? #t])
    (define headers '("Content-Type: application/ocsp-request"))
    (define req-b64
      (and try-get? (< (bytes-length req-der) 192)
           (bytes->string/utf-8 (base64-encode req-der))))
    (define resp-in
      (cond [req-b64 (get-impure-port (string->url (string-append ocsp-url "/" req-b64)) headers)]
            [else (post-impure-port (string->url ocsp-url) req-der headers)]))
    (define header (purify-port resp-in))
    (define resp-bytes (port->bytes resp-in))
    (close-input-port resp-in)
    (cond [(regexp-match? #rx"^HTTP/[0-9.]* 200" header)
           (bytes->ocsp-response resp-bytes)]
          [req-b64 (loop #f)]
          [else 'failed-to-fetch])))

(define SubjectPublicKeyInfo-shallow
  (SEQUENCE [algorithm ANY] [subjectPublicKey BIT-STRING]))

(define (certificate-keyhash cert)
  (define spki (bytes->asn1 SubjectPublicKeyInfo-shallow (send cert get-spki)))
  (define pk (bit-string-bytes (hash-ref spki 'subjectPublicKey)))
  (sha1-bytes pk))

(define (make-certid chain)
  (define cert (send chain get-certificate))
  (define issuer (send chain get-issuer-or-self))
  (hasheq 'hashAlgorithm (hasheq 'algorithm id-sha1)
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

;; bytes->ocsp-response : Bytes -> ocsp-response% or Symbol
(define (bytes->ocsp-response der)
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
           (null? (send responder-chain check-signature algid tbs-der sig))))

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
         (when (pair? more) (log-x509-error "multiple matching OCSP SingleResponses"))
         sr]
        [(list) #f]))

    (define/public (lookup-single-responses certid)
      (for/list ([sr (in-list (get-responses))]
                  #:when (certid=? (hash-ref sr 'certID) certid))
        sr))
    ))

(define DEFAULT-VALID-TIME (* 7 24 60 60))
(define (single-response-expiration-time resp)
  (cond [(hash-ref resp 'nextUpdate #f) => asn1-generalized-time->seconds]
        [else (+ (asn1-generalized-time->seconds (hash-ref resp 'thisUpdate))
                 DEFAULT-VALID-TIME)]))
