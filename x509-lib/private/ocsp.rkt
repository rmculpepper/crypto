#lang racket/base
(require racket/match
         racket/class
         racket/port
         net/url
         crypto
         crypto/private/common/base64
         asn1
         asn1/util/time
         (only-in "asn1.rkt" Name sig-alg->digest)
         (only-in "cert.rkt" Name-equal? bytes->certificate)
         "interfaces.rkt"
         "ocsp-asn1.rkt")
(provide (all-defined-out))

;; It seems that OCSP responders are very fragile and finicky.
;; - Might respond "malformed" if request does not use sha1.
;; - Might respond only to first certificate in request. (Probably to enable
;;   static responses.)
;; So: use sha1, limit request to single certificate.

;; check-not-revoked/ocsp : Chain -> LookupResult
(define (check-not-revoked/ocsp chain [at-time (current-seconds)]
                                #:cache [cache no-cache]
                                #:try-get? [try-get? #t])
  (define rs (get-ocsp-responses chain #:cache cache #:try-get? try-get?))
  (define certid (make-certid chain))
  (define result
    (lookup-result-join
     (for/list ([r (in-list rs)])
       (cond [(is-a? r ocsp-response%)
              (send r lookup chain certid)]
             [else 'unknown:no-responses]))))
  (match result
    [(? list?)
     (define result2
       (filter (match-lambda
                 [(list last-time next-time)
                  (<= last-time at-time next-time)])
               result))
     (cond [(pair? result2) result2]
           [else 'unknown:no-timely-responses])]
    [_ result]))

;; get-ocsp-responses : Chain -> (Listof (U ocsp-response% Symbol))
(define (get-ocsp-responses chain
                            #:cache [cache no-cache]
                            #:try-get? [try-get? #t])
  (define cert (send chain get-certificate))
  (define req-der (make-ocsp-request chain))
  (for/list ([ocsp-url (send cert get-ocsp-uris)])
    (define resp (send cache fetch-ocsp ocsp-url req-der do-fetch-ocsp))
    (when (is-a? resp ocsp-response%)
      (unless (send resp ok-signature? (send chain get-issuer-chain-or-self))
        (error 'ocsp "bad signature")))
    resp))

(define (do-fetch-ocsp ocsp-url req-der)
  (define try-get? #t) ;; FIXME!
  (define headers '("Content-Type: application/ocsp-request"))
  (define req-b64 (and try-get? (< (bytes-length req-der) 192) (b64-encode/utf-8 req-der)))
  (define resp-in
    (cond [req-b64 (get-pure-port (string->url (string-append ocsp-url "/" req-b64)) headers)]
          [else (post-pure-port (string->url ocsp-url) req-der headers)]))
  (define resp-bytes (port->bytes resp-in))
  (close-input-port resp-in)
  (bytes->ocsp-response resp-bytes))

(define SubjectPublicKeyInfo-shallow
  (SEQUENCE [algorithm ANY] [subjectPublicKey BIT-STRING]))

(define (certificate-keyhash cert)
  (define spki (bytes->asn1 SubjectPublicKeyInfo-shallow (send cert get-spki)))
  (define pk (bit-string-bytes (hash-ref spki 'subjectPublicKey)))
  (sha1-bytes pk))

(define (make-certid chain)
  (define cert (send chain get-certificate))
  (define issuer (send chain get-issuer-or-self))
  (hasheq 'hashAlgorithm (hasheq 'algorithm id-sha1 'parameters #f)
          'issuerNameHash (sha1-bytes (asn1->bytes/DER Name (send issuer get-subject)))
          'issuerKeyHash (certificate-keyhash issuer)
          'serialNumber (send cert get-serial-number)))

(define (make-ocsp-request chain)
  (define cert (send chain get-certificate))
  (define issuer (send chain get-issuer-or-self))
  (define certid (make-certid chain))
  (define reqlist
    (list (hasheq 'reqCert certid)))
  (define tbs
    (hasheq 'requestList reqlist))
  (define req
    (hasheq 'tbsRequest tbs))
  (asn1->bytes/DER OCSPRequest req))

;; bytes->ocsp-response : Bytes -> ocsp-response% or Symbol
(define (bytes->ocsp-response der)
  (define resp (bytes->asn1 OCSPResponse der))
  ;; (list (hash-ref resp 'responseStatus)
  (define rb (hash-ref resp 'responseBytes #f))
  (define rtype (and rb (hash-ref rb 'responseType)))
  (define rbody (and rb (hash-ref rb 'response)))
  (or (and (equal? rtype id-pkix-ocsp-basic) rbody
           (new ocsp-response% (rbody rbody)))
      (hash-ref resp 'responseStatus)))

(define ocsp-response%
  (class* object% (cachable<%>)
    (init-field rbody)
    (super-new)

    (define rdata (hash-ref rbody 'tbsResponseData))

    (define/public (get-response-data) rdata)
    (define/public (get-responder-id) (hash-ref rdata 'responderID))
    (define/public (get-produced-at) (hash-ref rdata 'producedAt))
    (define/public (get-responses) (hash-ref rdata 'responses))
    ;; FIXME: process extensions

    (define/public (get-expiration-time)
      (apply min
             (map asn1-generalized-time->seconds
                  (for/list ([resp (in-list (get-responses))]) (hash-ref resp 'nextUpdate)))))

    ;; Verify signature
    (define/public (ok-signature? issuer-chain)
      (define tbs-der (asn1->bytes/DER ResponseData rdata))
      (define di (sig-alg->digest (hash-ref rbody 'signatureAlgorithm)))
      (define sig (match (hash-ref rbody 'signature)
                    [(bit-string sig-bytes 0) sig-bytes]))
      (define responder-chain (get-responder-chain issuer-chain))
      (define responder-pk (and responder-chain (send responder-chain get-public-key)))
      (and responder-pk (digest/verify responder-pk di tbs-der sig)))

    (define/public (get-responder-chain issuer-chain)
      (define (is-responder? cert)
        (match (get-responder-id)
          [(list 'byName responder-name)
           (Name-equal? responder-name (send cert get-subject))]
          [(list 'byKey keyhash)
           (equal? keyhash (certificate-keyhash cert))]))
      (if (is-responder? (send issuer-chain get-certificate))
          issuer-chain
          (for/or ([cert-der (in-list (hash-ref rbody 'certs null))])
            (define cert (bytes->certificate cert-der))
            (and (is-responder? cert)
                 (let ([chain (send issuer-chain extend-chain cert)])
                   (and (certificate-chain? chain)
                        (send chain suitable-for-ocsp-signing? issuer-chain)
                        ;; We omit the store trust check because issuer-chain
                        ;; has (presumably) already been checked for trust, and
                        ;; the new chain has the same trust anchor.
                        (send chain trusted? #f)
                        chain))))))

    ;; lookup : Chain -> (Listof LookupResult)
    (define/public (lookup chain [certid (make-certid chain)])
      (lookup-result-join
       (for/list ([resp (in-list (get-responses))])
         (cond [(equal? (hash-ref resp 'certID) certid)
                (match (hash-ref resp 'certStatus)
                  [(list 'good _)
                   (list (list (asn1-generalized-time->seconds (hash-ref resp 'thisUpdate))
                               (asn1-generalized-time->seconds (hash-ref resp 'nextUpdate))))]
                  [(list 'revoked _) 'revoked]
                  [(list 'unknown _) 'unknown])]
               [else 'unknown]))))
    ))

;; A LookupResult is one of
;; - 'unknown
;; - 'revoked
;; - (listof (list Seconds Seconds))

(define (lookup-result-join xs)
  (foldl lookup-result-join2 'unknown xs))

(define (lookup-result-join2 x y)
  (match* [x y]
    [['unknown y] y]
    [[x 'unknown] x]
    [['revoked _] 'revoked]
    [[_ 'revoked] 'revoked]
    [[(? list? x) (? list? y)] (append x y)]))

(define (max+ a b) (if (and a b) (max a b) (or a b)))
(define (min+ a b) (if (and a b) (min a b) (or a b)))
