#lang racket/base
(require racket/match
         racket/class
         crypto
         asn1
         (only-in "asn1.rkt" Name relation-ref SIGNING)
         "ocsp-asn1.rkt")
(provide (all-defined-out))

(define SubjectPublicKeyInfo-shallow
  (SEQUENCE [algorithm ANY] [subjectPublicKey BIT-STRING]))

(define (make-ocsp-request cert issuer)
  (define issuer-spki (bytes->asn1 SubjectPublicKeyInfo-shallow (send issuer get-spki)))
  (define issuer-pk (bit-string-bytes (hash-ref issuer-spki 'subjectPublicKey)))
  (define certid
    (hasheq 'hashAlgorithm (hasheq 'algorithm id-sha1 'params #f)
            'issuerNameHash (sha1-bytes (asn1->bytes/DER Name (send issuer get-subject)))
            ;;'issuerNameHash (sha1-bytes (asn1->bytes/DER Name (send cert get-issuer)))
            'issuerKeyHash (sha1-bytes issuer-pk)
            ;;'issuerKeyHash (sha1-bytes (send issuer get-spki))
            'serialNumber (send cert get-serial-number)))
  (define reqlist
    (list (hasheq 'reqCert certid)))
  (define tbs
    (hasheq 'requestList reqlist))
  (define req
    (hasheq 'tbsRequest tbs))
  (asn1->bytes/DER OCSPRequest req))

(define (bytes->ocsp-response der)
  (define resp (bytes->asn1 OCSPResponse der))
  (define rb (hash-ref resp 'responseBytes #f))
  (define rtype (and rb (hash-ref rb 'responseType)))
  (define rbody (and rb (hash-ref rb 'response)))
  (unless (equal? rtype id-pkix-ocsp-basic)
    (error 'ocsp-response% "bad response type: ~e" rtype))
  (new ocsp-response% (rbody rbody) (rdata (hash-ref rbody 'tbsResponseData))))

(define ocsp-response%
  (class object%
    (init-field rbody rdata)
    (super-new)

    (define/public (get-response-data) rdata)
    (define/public (get-responder-id) (hash-ref rdata 'responderID))
    (define/public (get-produced-at) (hash-ref rdata 'producedAt))
    (define/public (get-responses) (hash-ref rdata 'responses))
    ;; FIXME: process extensions

    ;; Verify signature
    (define/public (ok-signature? responder-pk)
      (define tbs-der (asn1->bytes/DER ResponseData rdata))
      (define alg (hash-ref rbody 'signatureAlgorithm))
      (define alg-oid (hash-ref alg 'algorithm))
      (unless (eq? #f (hash-ref alg 'parameters #f))
        (error 'ok-signature? "internal error: parameters not supported"))
      (define sig (match (hash-ref rbody 'signature)
                    [(bit-string sig-bytes 0) sig-bytes]))
      (define di (relation-ref SIGNING 'oid alg-oid 'digest))
      (digest/verify responder-pk di tbs-der sig))

    ))

(require net/url racket/port)
(require crypto/private/common/base64)

(define (perform-ocsp cert issuer)
  (for/list ([ocsp-url (send cert get-ocsp-uris)])
    (define resp-in
      (post-impure-port (string->url ocsp-url)
                        (make-ocsp-request cert issuer)
                        (list "Content-Type: application/ocsp-request")))
    (define header (purify-port resp-in))
    ;;(printf "header = ~s\n" header)
    (define resp-bytes (port->bytes resp-in))
    (close-input-port resp-in)
    (bytes->ocsp-response resp-bytes)))
