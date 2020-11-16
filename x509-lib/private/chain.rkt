#lang racket/base
(require racket/class
         racket/match
         racket/list
         "interfaces.rkt"
         "cert-data.rkt"
         "cert.rkt"
         "crl.rkt")
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

    ;; ----------------------------------------

    (define/public (check-revocation/crl #:cache [cache the-crl-cache]
                                         #:who [who 'check-revocation/crl])
      ;; Check end-certificate for revocation
      ;; FIXME: check all certs
      ;; FIXME: require CRL issuer to be same as cert issuer
      (define end-cert (get-end-certificate))
      (define crl-dists (send end-cert get-crl-distribution-points))
      (define crl-urls
        (flatten
         (for/list ([crl-dist (in-list crl-dists)]
                    ;; FIXME: we only handle case where CRL issuer is same as cert issuer
                    #:when (not (hash-has-key? crl-dist 'cRLIssuer)))
           (match (hash-ref crl-dist 'distributionPoint #f)
             [(list 'fullName gnames)
              (for/list ([gname (in-list gnames)])
                (match gname
                  [(list 'uniformResourceIdentifier
                         (and (regexp #rx"^https?://") url))
                   (list url)]
                  [_ null]))]
             [_ null]))))
      (unless (pair? crl-urls)
        (error who "no supported CRL distribution points\n  certificate: ~e"
               end-cert))
      (define serial-number (send end-cert get-serial-number))
      (for ([crl-url (in-list crl-urls)])
        (define crl (send the-crl-cache get-crl crl-url))
        ;; FIXME: check crl signature
        ;; What to do if fetch fails or if signature fails?
        (when (member serial-number (send crl get-revoked-serial-numbers))
          (error who "revoked"))))
    ))

;; ============================================================

;; The pre-chain% class contains code used to check chain-validity. The
;; certificate-chain% subclass represents a good chain; bad-chain% represents a
;; bad chain and includes errors. This allows implementation sharing while
;; preserving the invariant that a certificate-chain% object is chain-valid.

(define pre-chain%
  (class object%
    (init-field issuer-chain  ;; Chain or #f if anchor
                cert)         ;; Certificate
    (super-new)

    (define/public (get-issuer-chain) issuer-chain)
    (define/public (get-certificate) cert)

    (define/public (get-subject) (send cert get-subject))
    (define/public (get-public-key) (send cert get-public-key))
    (define/public (get-index) index)

    ;; index : Nat  -- 0 is anchor
    (define index (if issuer-chain (add1 (send issuer-chain get-index)) 0))

    ;; max-path-length : Integer or #f
    ;; The maximum number of *intermediate* certificates that can *follow* this one.
    ;; Thus if zero, can still extend with end certificate but not new intermediate.
    ;; If less than zero, cannot extend; but -1 is okay for end certificate.
    (define max-path-length
      (let* ([issuer-max-path-length (send issuer-chain get-max-path-length)]
             [max-path-length
              ;; 6.1.4 (h, l) decrement counters
              (and issuer-max-path-length
                   (- issuer-max-path-length (if (is-self-issued?) 0 1)))]
             [max-path-length
              ;; 6.1.4 (m)
              (let* ([ext (get-extension-value id-ce-basicConstraints)]
                     [plen (and ext (hash-ref ext 'pathLenConstraint #f))])
                (cond [(and plen (< plen (or max-path-length +inf.0))) plen]
                      [else max-path-length]))])
        max-path-length))

    ;; name-constraints : ParsedNameConstraints
    ;; Only for the current certificate; see recursive check-name-constraints.
    ;; 6.1.4 (g) name constraints
    (define name-constraints
      (cond [(send cert get-name-constraints)
             => (lambda (ncs) (extend-name-constraints null index ncs))]
            [else null]))

    ;; {from,to}-time : Seconds
    (define-values (from-time to-time)
      (match (and issuer-chain (send issuer-chain get-validity-period))
        [(list issuer-from issuer-to)
         (match-define (list cert-from cert-to) (send cert get-validity-period))
         (values (max cert-from issuer-from) (min cert-to issuer-to))]
        [else (send cert get-validity-period)]))

    (define/public (get-validity-period)
      (list from-time to-time))

    (define/public (check-as-intermediate)
      ;; 6.1.4
      (append
       ;; 6.1.4 (a-b) policy-mappings, policies, ...
       #| POLICIES NOT SUPPORTED |#
       ;; 6.1.4 (c-f) handled by get-public-key method instead
       ;; 6.1.4 (g) name constraints -- in constructor
       ;; 6.1.4 (h, l) decrement counters -- in constructor
       (cond [(>= max-path-length 0) '()]
             [else '(intermediate:max-path-length)])
       ;; 6.1.4 (i, j) policy-mapping, inhibit-anypolicy, ...
       #| POLICIES NOT SUPPORTED |#
       ;; 6.1.4 (k) check CA (reject if no basicConstraints extension)
       (cond [(is-CA?) '()]
             [else '(intermediate:not-CA)])
       ;; 6.1.4 (m) -- in constructor
       ;; 6.1.4 (n)
       (cond [(ok-key-use? 'keyCertSign #t) '()]
             [else '(intermediate:missing-keyCertSign)])
       ;; 6.1.4 (o) process other critical extensions: errors gathered in construction
       #| checked in certificate% |#))

    (define/public (check-as-final-chain)
      ;; 6.1.5
      (begin
        ;; 6.1.5 (a,b) explicit-policy, policies
        (void 'POLICIES-UNSUPPORTED)
        ;; 6.1.5 (c-e) handled by get-public-key method instead
        (void 'OK)
        ;; 6.1.5 (f) process other critical extensions: errors gathered in construction
        (void 'DONE-DURING-CONSTRUCTION)
        ;; 6.1.5 (g) policies ...
        (void 'POLICIES-UNSUPPORTED))
      null)

    ;; ----------------------------------------
    ;; Extension

    (define/public (extend-chain new-cert)
      (define errors
        (append (check-as-intermediate)
                (check-chain-addition new-cert)))
      (cond [(pair? errors)
             (new bad-chain% (issuer-chain this) (cert new-cert) (errors errors))]
            [else (new certificate-chain% (issuer-chain this) (cert new-cert))]))

    ;; check-with-issuer-chain : Chain -> ErrList
    (define/public (check-chain-addition new-cert)
      (define (add-index what) (cons (add1 index) what))
      ;; 6.1.3
      (append
       ;; 6.1.3 (a)(1) verify signature
       (map add-index (check-certificate-signature new-cert))
       ;; 6.1.3 (a)(2) currently valid
       (match (send new-cert get-validity-period)
         [(list cert-from cert-to)
          (cond [(<= (max from-time cert-from) (min to-time cert-to)) '()]
                [else (map add-index '(validity-period:empty-intersection))])])
       ;; 6.1.3 (a)(3) (not revoked)
       #| CRL NOT SUPPORTED |#
       ;; 6.1.3 (a)(4) issuer
       (cond [(Name-equal? (get-issuer) (send issuer-chain get-subject)) '()]
             [else (map add-index '(issuer:name-mismatch))])
       ;; 6.1.3 (b,c) check name constraints
       (cond [(and (is-self-issued?) (not final-in-path?)) null]
             [else
              (define subject-name (send new-cert get-subject))
              (define alt-names (send new-cert get-subject-alt-name))
              (map add-index
                   (append (check-name-constraints (list 'directoryName subject-name) 'subject)
                           (append* (for/list ([san (in-list alt-names)])
                                      (check-name-constraints san 'alt)))))])
       ;; 6.1.3 (d-f) process policies; set/check valid-policy-tree, explicit-policy
       #| POLICIES NOT SUPPORTED |#))

    (define/public (check-certificate-signature new-cert)
      (if (send new-cert ok-signature? (get-public-key)) '() '(bad-signature)))

    (define/public (check-name-constraints gname kind)
      ;; 6.1.4 (g) name constraints
      (append
       (cond [(name-constraints-name-ok? name-constraints name) null]
             [else (case kind
                     [(subject) (list (cons index 'name-constraints:subject-rejected))]
                     [else (list (cons index 'name-constraints:subjectAltName-rejected))])])
       (if issuer-chain (send issuer-chain check-name-constraints gname kind) null)))

    ;; ----------------------------------------
    ;; Checking suitability for a purpose

    (define/public (suitable-for-tls-server? host)
      (null? (check-suitable-for-tls-server host)))

    (define/public (check-suitable-for-tls-server host)
      (send (get-end-certificate) check-suitable-for-tls-server host))
    ))

(define bad-chain%
  (class* pre-chain%
    (inherit-field issuer-chain)
    (init-field errors)
    (super-new)
    (define/public (get-errors)
      (append errors
              (cond [(is-a? issuer-chain bad-chain%)
                     (send issuer-chain get-errors)]
                    [else null])))
    ))

(define certificate-chain%
  (class* pre-chain% (-certificate-chain<%>)
    (inherit-field issuer-chain cert)
    (super-new)
    ))
