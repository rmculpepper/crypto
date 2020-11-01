#lang racket/base
(require racket/class
         racket/list
         "interfaces.rkt"
         "cert-data.rkt"
         "cert.rkt")
(provide (all-defined-out))

;; References:
;; - RFC 5280 (https://tools.ietf.org/html/rfc5280)
;; - RFC 6818 (general updates) (https://tools.ietf.org/html/rfc6818)
;; - RFC 8398 and 8399 (Internationalization) (https://tools.ietf.org/html/rfc8398,
;;   https://tools.ietf.org/html/rfc8399)

;; FIXME: asn1 parser returns mutable bytes,strings?

;; FIXME: need mechanism for disallowing obsolete algorithms (eg, 1024-bit RSA / DSA)

;; recursive verification arguments
;; - chain
;; - hostname (optional)
;; - purposes (recur with purposes={CA}?)
;; - depth (decrement --- or just do depth check once?)

;; constant verification arguments
;; - when (allow range?)
;; - download CRLs? use OSCP?
;;   - if so, use cache? (storage location, cache params, etc)
;; - trusted certificate roots (CA or not?)
;; - ? untrusted intermediate certificates (if chain is not explicit?)
;;   - option to automatically fetch intermediate certificates? (feasible?)

;; success output:
;; - verified chain (ending in explicit self-signed (CA?) cert? maybe not necessarily)
;; - public key (of top cert)
;; - warnings?

;; failure output:
;; - failure details?

;; ============================================================

;; A CandidateChain is (list TrustAnchor Cert ...),
;; where TrustAnchor is currently always also a Cert.

;; check-candidate-chain : CandidateChain -> (values CertificateChain/#f ErrorList)
;; Checks the properties listed under certificate-chain%. Also checks that the
;; chain's validity period includes the given valid-time argument.
(define (check-candidate-chain certs valid-time)
  (when (null? certs) (error 'get-chain-errors "empty candidate chain"))
  (define N (sub1 (length certs))) ;; don't count trust anchor
  (define vi (new validation% (N N)))
  (send (car certs) check-valid-period 0 vi valid-time valid-time)
  (for ([issuer (in-list certs)]
        [cert (in-list (cdr certs))]
        [index (in-naturals 1)])
    (send cert check-valid-period index vi valid-time valid-time)
    (send cert check-link-in-chain index issuer vi (= index N)))
  (define ok-start (send vi get-from-time))
  (define ok-end (send vi get-to-time))
  (define errs (send vi get-errors))
  (cond [(null? errs)
         (define chain
           (new certificate-chain% (chain certs)
                (ok-start ok-start) (ok-end ok-end)))
         (values chain null)]
        [else
         (values #f errs)]))

;; validation% represents (mutable) state during chain validation
(define validation%
  (class object%
    (init N)
    (init-field [max-path-length N]
                [from-time #f]
                [to-time #f]
                [name-constraints null]
                [explicit-policy (add1 N)]
                [policy-mapping (add1 N)]
                [inhibit-anypolicy (add1 N)]
                [errors null]) ;; ErrorList, mutated
    (super-new)

    (define/public (decrement-counters) ;; 6.1.4 (b)
      (cond [(positive? max-path-length)
             (set! max-path-length (sub1 max-path-length))]
            [else (add-error 'max-path-length)])
      (unless (zero? explicit-policy) (set! explicit-policy (sub1 explicit-policy)))
      (unless (zero? policy-mapping) (set! policy-mapping (sub1 policy-mapping)))
      (unless (zero? inhibit-anypolicy) (set! inhibit-anypolicy (sub1 inhibit-anypolicy))))

    (define/public (intersect-valid-period from to)
      (set! from-time (if from-time (max from from-time) from))
      (set! to-time (if to-time (min to to-time) to)))

    (define/public (get-from-time) from-time)
    (define/public (get-to-time) to-time)

    (define/public (get-errors) errors)
    (define/public (add-error what) (set! errors (cons what errors)))

    (define/public (add-name-constraints index ncs)
      (when ncs (set! name-constraints (extend-name-constraints name-constraints index ncs))))

    (define/public (name-constraints-accept? gname)
      (name-constraints-name-ok? name-constraints gname))

    (define/public (set-max-path-length n)
      (when (< n max-path-length) (set! max-path-length n)))
    ))

;; ============================================================

;; A CertificateChain is an instance of certificate-chain%, containing a
;; non-empty list of certs of the form (list trust-anchor ... end-cert).

;; A certificate chain is "chain-valid" if it satisfies all of the following:
;; - each cert issued the next, and signatures are valid
;; - the intersection of each cert's validity period is not empty
;;   (the intersection of the validity periods is stored)
;; - name constraints, path length constraints, etc are checked
;; Beware the following limitations of "chain-validity":
;; - It DOES NOT check that the trust anchor is actually trusted.
;; - It DOES NOT check that the end-certificate is suitable for any particular purpose.

;; A certificate chain is "trusted" given a x509-store and a time interval if it
;; satisfies all of the following:
;; - it is "chain-valid"
;; - the chain's validity period includes the given time interval
;; - the chain's trust anchor is trusted by the given x509-store

;; A certificate chain is "valid for a purpose" if
;; - the chain is "trusted", and
;; - the chain's end-certificate is suitable for the given purpose

;; A certificate is "suitable for a purpose of identifying a TLS server" if
;; - the cert's subjectAlternativeName contains a dNSName pattern that matches
;;   the TLS server's fully-qualified host name
;; - OPTIONAL: ... sufficient security level of algorithms ...
;; - OPTIONAL: ... validity period < some limit (825 days) ...
;; - If KeyUsage is present, must contain at least one of
;;     digitalSignature, keyEncipherment, keyAgreement.
;;   (IIUC (??), cannot be more precise w/o knowing TLS ciphersuite negotiated.)
;; - If ExtendedKeyUsage is present, then it must contain id-kp-serverAuth.
;; - References:
;;   - https://tools.ietf.org/html/rfc5246#section-7.4.2
;;   - https://tools.ietf.org/html/rfc5280#section-4.2.1.12

(define certificate-chain%
  (class* object% (-certificate-chain<%>)
    ;; chain : (list trust-anchor<%> certificate% ...+)
    ;; Note: In 6.1, trust anchor is not considered part of chain.
    (init-field chain ok-start ok-end)
    (super-new)

    (define/public (custom-write out mode)
      (fprintf out "#<certificate-chain: ~a>"
               (Name->string (send (get-end-certificate) get-subject))))

    (define N (length (cdr chain))) ;; don't count trust anchor

    (define/public (get-chain) chain)
    (define/public (get-end-certificate) (last chain))
    (define/public (get-trust-anchor) (first chain))

    (define/public (trusted? store [from-time (current-seconds)] [to-time from-time])
      (null? (check-trust store from-time to-time)))

    ;; check-trust : Store Seconds Seconds -> ErrorList
    (define/public (check-trust store [from-time (current-seconds)] [to-time from-time])
      (append (cond [(send store trust? (get-trust-anchor)) '()]
                    [else '((0 . trust-anchor:not-trusted))])
              (cond [(<= ok-start from-time to-time ok-end) '()]
                    [else
                     (let ([vi (new validation% (N (sub1 (length chain)))
                                    (from-time from-time) (to-time to-time))])
                       (for ([cert (in-list chain)] [index (in-naturals 1)])
                         (send cert check-valid-period index vi from-time to-time)))])))
    ))
