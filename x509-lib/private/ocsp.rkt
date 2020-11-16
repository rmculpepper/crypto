#lang racket/base
(require racket/match
         racket/class
         crypto
         asn1
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

(define SubjectPublicKeyInfo-shallow
  (SEQUENCE [algorithm ANY] [subjectPublicKey BIT-STRING]))

(define (certificate-keyhash cert)
  (define spki (bytes->asn1 SubjectPublicKeyInfo-shallow (send cert get-spki)))
  (define pk (bit-string-bytes (hash-ref spki 'subjectPublicKey)))
  (sha1-bytes pk))

(define (make-certid chain)
  (define cert (send chain get-certificate))
  (define issuer (send chain get-issuer-or-self))
  (hasheq 'hashAlgorithm (hasheq 'algorithm id-sha1 'params #f)
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

(define (bytes->ocsp-response der)
  (define resp (bytes->asn1 OCSPResponse der))
  (list (hash-ref resp 'responseStatus)
        (let ()
          (define rb (hash-ref resp 'responseBytes #f))
          (define rtype (and rb (hash-ref rb 'responseType)))
          (define rbody (and rb (hash-ref rb 'response)))
          (unless (equal? rtype id-pkix-ocsp-basic)
            (error 'ocsp-response% "bad response type: ~e" rtype ))
          (and rbody (new ocsp-response% (rbody rbody))))))

(define ocsp-response%
  (class object%
    (init-field rbody)
    (super-new)

    (define rdata (hash-ref rbody 'tbsResponseData))

    (define/public (get-response-data) rdata)
    (define/public (get-responder-id) (hash-ref rdata 'responderID))
    (define/public (get-produced-at) (hash-ref rdata 'producedAt))
    (define/public (get-responses) (hash-ref rdata 'responses))
    ;; FIXME: process extensions

    ;; Verify signature
    (define/public (ok-signature? issuer-chain)
      (define tbs-der (asn1->bytes/DER ResponseData rdata))
      (define di (sig-alg->digest (hash-ref rbody 'signatureAlgorithm)))
      (define sig (match (hash-ref rbody 'signature)
                    [(bit-string sig-bytes 0) sig-bytes]))
      (define responder-chain (get-responder-chain issuer-chain))
      (define responder-pk (send responder-chain get-public-key))
      (digest/verify responder-pk di tbs-der sig))

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
    ))

(require net/url racket/port)
(require crypto/private/common/base64)

(define (perform-ocsp chain)
  (define cert (send chain get-certificate))
  (for/list ([ocsp-url (send cert get-ocsp-uris)])
    (define resp-in
      (post-impure-port (string->url ocsp-url)
                        (make-ocsp-request chain)
                        (list "Content-Type: application/ocsp-request")))
    (define header (purify-port resp-in))
    ;;(printf "header = ~s\n" header)
    (define resp-bytes (port->bytes resp-in))
    (close-input-port resp-in)
    (match (bytes->ocsp-response resp-bytes)
      [(list status ocsp)
       (when ocsp
         (unless (send ocsp ok-signature? (send chain get-issuer-chain-or-self))
           (error 'ocsp "bad signature")))
       (list status ocsp)])))
