#lang racket/base
(require racket/class
         racket/match
         racket/list
         racket/serialize
         crypto
         "interfaces.rkt"
         "asn1.rkt"
         (submod "asn1.rkt" verify)
         "cert.rkt")
(provide (all-defined-out))

;; References:
;; - RFC 5280 (https://tools.ietf.org/html/rfc5280)
;; - RFC 6818 (general updates) (https://tools.ietf.org/html/rfc6818)
;; - RFC 8398 and 8399 (Internationalization) (https://tools.ietf.org/html/rfc8398,
;;   https://tools.ietf.org/html/rfc8399)
;; - CA/Browser Forum Baseline Recommendations (v1.7.3)

;; ============================================================

;; anchor-cache : WeakHasheq[Certificate => CertChain]
(define anchor-cache (make-weak-hasheq))

(define (make-anchor-chain cert)
  (define (do-make-anchor-chain)
    (new certificate-chain% (issuer-chain #f) (cert cert)))
  (hash-ref! anchor-cache cert do-make-anchor-chain))

;; A CandidateChain is (list TrustAnchor Cert ...),
;; where TrustAnchor is currently always also a Cert.

;; check-candidate-chain : CandidateChain -> (values CertificateChain/#f ErrorList)
;; Checks the properties listed under certificate-chain%.
(define (check-candidate-chain certs)
  (define pre-chain
    (for/fold ([chain (make-anchor-chain (car certs))])
              ([cert (in-list (cdr certs))])
      (send chain extend-chain cert)))
  (cond [(is-a? pre-chain bad-chain%)
         (values #f (send pre-chain get-errors))]
        [(is-a? pre-chain certificate-chain%)
         (values pre-chain null)]))

;; ============================================================

;; A CertificateChain is an instance of certificate-chain%.

;; A certificate chain is "chain-valid" if it satisfies all of the following:
;; - each cert issued the next, and signatures are valid
;;   (Note that the trust anchor's signature is not verified; the trust
;;   anchor may or may not be self-signed.)
;; - the intersection of each cert's validity period is not empty
;;   (the intersection of the validity periods is stored)
;; - name constraints, path length constraints, etc are checked
;; Beware the following limitations of "chain-validity":
;; - It DOES NOT check that the trust anchor is actually trusted.
;; - It DOES NOT check that the chain is valid at the current time.
;; - It DOES NOT check that the end-certificate is suitable for any particular purpose.

;; A certificate chain is "trusted" given a x509-store and a time interval if it
;; satisfies all of the following:
;; - it is "chain-valid"
;; - the chain's validity period includes the given time interval
;; - the chain's trust anchor is trusted by the given x509-store

;; A certificate chain is "valid for a purpose" if
;; - the chain is "trusted", and
;; - the chain's end-certificate is suitable for the given purpose

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

    (define/public (get-certificates)
      (cons cert (if issuer-chain (send issuer-chain get-certificates) null)))

    (define/public (get-issuer-chain-or-self)
      (or issuer-chain this))
    (define/public (get-issuer-or-self)
      (send (get-issuer-chain-or-self) get-certificate))

    (define/public (get-anchor-chain)
      (if issuer-chain (send issuer-chain get-anchor-chain) this))
    (define/public (get-anchor)
      (send (get-anchor-chain) get-certificate))
    (define/public (is-anchor?) (not issuer-chain))

    (define/public (get-subject) (send cert get-subject))
    (define/public (get-subject-alt-names [kind #f])
      (send cert get-subject-alt-names kind))
    (define/public (get-index) index)
    (define/public (get-max-path-length) max-path-length)

    ;; ----------------------------------------

    ;; public-key-cache : WeakHasheq[Factory/s => pk-key?]
    ;; The factories can change; cache for current factories.
    (define public-key-cache (make-weak-hasheq))

    (define/public (get-public-key [factory/s (crypto-factories)])
      (hash-ref! public-key-cache factory/s
                 (lambda ()
                   (parameterize ((crypto-factories factory/s))
                     (datum->pk-key (send cert get-spki) 'SubjectPublicKeyInfo)))))

    (define/public (check-signature algid tbs sig)
      (check-signature/algid (get-public-key) algid tbs sig))

    ;; ----------------------------------------

    ;; index : Nat  -- 0 is anchor
    (define index (if issuer-chain (add1 (send issuer-chain get-index)) 0))

    ;; max-path-length : Integer or #f
    ;; The maximum number of *intermediate* certificates that can *follow* this one.
    ;; Thus if zero, can still extend with end certificate but not new intermediate.
    ;; If less than zero, cannot extend; but -1 is okay for end certificate.
    (define max-path-length
      (let* ([issuer-max-path-length
              (and issuer-chain (send issuer-chain get-max-path-length))]
             [max-path-length
              ;; 6.1.4 (h, l) decrement counters
              (and issuer-max-path-length
                   (- issuer-max-path-length
                      (if (send cert is-self-issued?) 0 1)))]
             [max-path-length
              ;; 6.1.4 (m)
              (let* ([ext (send cert get-extension-value id-ce-basicConstraints #f)]
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

    (define/public (ok-extended-key-usage? eku [on-unset #f])
      ;; This code attempts to follow the CA/B Basic Requirements interpretation
      ;; of EKU extensions in CA certificates, mainly following OpenSSL's tests
      ;; to resolve ambiguities. In particular:
      ;; - If a CA contains the EKU extension, then the effective EKUs of any
      ;;   descendent are limited to the EKUs in the CA cert. (If the descendent
      ;;   contains others, they are ignored, but the cert is not considered
      ;;   invalid.)
      ;; - Clarifications, with the issuer is written on the left of the arrow:
      ;;   - In a chain with {eku} -> {} -> {eku}, eku is NOT in the set of
      ;;     effective EKUs.
      ;;   - In a chain with {eku} -> unset -> {eku}, eku is in the set of
      ;;     effective EKUs.
      ;;   - In a chain ending with {eku} -> unset, eku is NOT in the set of
      ;;     effective EKUs.
      ;; - In summary, in an intermediate cert, unset is equivalent to allowing
      ;;   all EKUs; in a leaf cert, it is equivalent to {}.
      (define (join cert-result issuer-result) ;; (U 'yes 'no 'unset)
        (case issuer-result
          [(yes) (case cert-result [(yes) 'yes] [(no) 'no] [(unset) 'unset])]
          [(no) 'no]
          [(unset) cert-result]))
      (define result (foldr join 'unset (get-eku-chain eku)))
      (case result [(yes) #t] [(no) #f] [else on-unset]))

    ;; get-eku-chain : OID -> (Listof (U 'yes 'no 'unset)), leaf first, root CA last
    (define/public (get-eku-chain eku)
      (cons (send cert get-eku eku)
            (if issuer-chain (send issuer-chain get-eku-chain eku) '())))

    ;; {from,to}-time : Seconds
    (define-values (from-time to-time)
      (let ()
        (match-define (list cert-from cert-to) (send cert get-validity-seconds))
        (match (and issuer-chain (send issuer-chain get-validity-seconds))
          [(list issuer-from issuer-to)
           (values (max cert-from issuer-from) (min cert-to issuer-to))]
          [else (values cert-from cert-to)])))

    (define/public (get-validity-seconds)
      (list from-time to-time))

    (define/public (print-chain)
      (let loop ([chain this])
        (when chain
          (eprintf "~s : ~e\n" (send chain get-index) chain)
          (loop (send chain get-issuer-chain)))))

    ;; ----------------------------------------
    ;; Extension

    (define extension-cache (make-weak-hasheq))

    (define/public (extend-chain new-cert)
      (hash-ref! extension-cache new-cert
                 (lambda ()
                   (define errors
                     (append (check-as-intermediate)
                             (check-chain-addition new-cert)
                             (get-errors)))
                   (cond [(pair? errors)
                          (new bad-chain% (issuer-chain this) (cert new-cert) (errors errors))]
                         [else (new certificate-chain% (issuer-chain this) (cert new-cert))]))))

    (define/public (get-errors) null)

    ;; check-as-intermediate : -> ErrList
    (define/public (check-as-intermediate)
      (define (add-index what) (cons (get-index) what))
      ;; 6.1.4
      (append
       ;; 6.1.4 (a-b) policy-mappings, policies, ...
       #| POLICIES NOT SUPPORTED |#
       ;; 6.1.4 (c-f) handled by get-public-key method instead
       ;; 6.1.4 (g) name constraints -- in constructor
       ;; 6.1.4 (h, l) decrement counters -- in constructor
       (cond [(>= (or max-path-length +inf.0) 0) '()]
             [else (map add-index '(intermediate:max-path-length))])
       ;; 6.1.4 (i, j) policy-mapping, inhibit-anypolicy, ...
       #| POLICIES NOT SUPPORTED |#
       ;; 6.1.4 (k) check CA (reject if no basicConstraints extension)
       (cond [(send cert is-CA?) '()]
             [else (map add-index '(intermediate:not-CA))])
       ;; 6.1.4 (m) -- in constructor
       ;; 6.1.4 (n)
       (cond [(send cert ok-key-usage? 'keyCertSign #t) '()]
             [else (map add-index '(intermediate:missing-keyCertSign))])
       ;; 6.1.4 (o) process other critical extensions: errors gathered in construction
       #| checked in certificate% |#))

    ;; check-as-final : -> ErrList
    (define/public (check-as-final)
      (append
       ;; 6.1.3 (b,c) -- deferred
       (if issuer-chain (send issuer-chain check-certificate-name-constraints cert) '())
       ;; 6.1.5
       ;; 6.1.5 (a,b) explicit-policy, policies
       #| POLICIES NOT SUPPORTED |#
       ;; 6.1.5 (c-e) handled by get-public-key method instead
       ;; 6.1.5 (f) process other critical extensions: errors gathered in construction
       ;; 6.1.5 (g) policies ...
       #| POLICIES NOT SUPPORTED |#))

    ;; check-with-issuer-chain : Chain -> ErrList
    (define/public (check-chain-addition new-cert)
      (define (add-index what) (cons (add1 index) what))
      ;; 6.1.3
      (append
       ;; 6.1.3 (a)(1) verify signature
       (map add-index (check-certificate-signature new-cert))
       ;; 6.1.3 (a)(2) currently valid
       (match (send new-cert get-validity-seconds)
         [(list cert-from cert-to)
          (cond [(<= (max from-time cert-from) (min to-time cert-to)) '()]
                [else (map add-index '(validity-period:empty-intersection))])])
       ;; 6.1.3 (a)(3) (not revoked)
       #| CRL checked separately |#
       ;; 6.1.3 (a)(4) issuer
       (cond [(Name-equal? (send new-cert get-issuer) (get-subject)) '()]
             [else (map add-index '(issuer:name-mismatch))])
       ;; 6.1.3 (b,c) check name constraints
       (cond [(send new-cert is-self-issued?)
              ;; Check self-issued cert's name constraints only if final.
              ;; So skip now, add to check-for-final
              null]
             [else (map add-index (check-certificate-name-constraints new-cert))])
       ;; 6.1.3 (d-f) process policies; set/check valid-policy-tree, explicit-policy
       #| POLICIES NOT SUPPORTED |#))

    (define/public (check-certificate-signature new-cert)
      (define-values (algid tbs-der sig) (send new-cert get-cert-signature-info))
      (check-signature algid tbs-der sig))

    (define/public (check-certificate-name-constraints new-cert)
      (define subject-name (send new-cert get-subject))
      (define alt-names (send new-cert get-subject-alt-names))
      (append
       (check-name-constraints (list 'directoryName subject-name) 'subject)
       (append*
        (match subject-name
          [(list 'rdnSequence rdns)
           (for*/list ([rdn (in-list rdns)] [av (in-list rdn)]
                       #:when (equal? (hash-ref av 'type) id-emailAddress))
             (check-name-constraints (list 'rfc822Name (hash-ref av 'value)) 'subject-email))]))
       (append* (for/list ([san (in-list alt-names)])
                  (check-name-constraints san 'alt)))))

    (define/public (check-name-constraints gname kind)
      ;; 6.1.4 (g) name constraints
      (append
       (cond [(name-constraints-name-ok? name-constraints gname) null]
             [else (case kind
                     [(subject) (list (cons index 'name-constraints:subject-rejected))]
                     [(subject-email) (list (cons index 'name-constraint:subject-email-rejected))]
                     [else (list (cons index 'name-constraints:subjectAltName-rejected))])])
       (if issuer-chain (send issuer-chain check-name-constraints gname kind) null)))

    (define/public (check-validity-period from-time to-time)
      (match-define (list ok-start ok-end) (get-validity-seconds))
      (cond [(<= ok-start from-time to-time ok-end) '()]
            [else
             (cons (cons index 'validity-period:not-contained)
                   (if issuer-chain
                       (send issuer-chain check-validity-period from-time to-time)
                       null))]))

    ;; ----------------------------------------
    ;; Checking security level

    (define/public (get-security-bits-chain)
      (cons (send (get-public-key) get-security-bits)
            (cond [issuer-chain
                   (cons (let-values ([(algid _tbs _sig) (send cert get-cert-signature-info)])
                           (sig-alg-security-bits algid))
                         (send issuer-chain get-security-bits-chain))]
                  [else null])))

    (define/public (check-security-bits sec-bits)
      (append
       (let ([pk (get-public-key)])
         (cond [(<= sec-bits (send pk get-security-bits)) '()]
               ;; Note: here index means owner of public key.
               [else (list (cons index 'security-level:weak-public-key))]))
       (cond [issuer-chain
              (define-values (algid _tbs _sig) (send cert get-cert-signature-info))
              (define sig-level (sig-alg-security-bits algid))
              (append (cond [(<= sec-bits sig-level) '()]
                            ;; Note: here index means site of signature (created by issuer!).
                            [else (list (cons index 'security-level:weak-signature-algorithm))])
                      (send issuer-chain check-security-bits sec-bits))]
             [else null])))

    (define/public (check-security-level level)
      (check-security-bits
       (case level [(0) 0] [(1) 80] [(2) 112] [(3) 128] [(4) 192] [(5) 256] [else 256])))
    ))

(define bad-chain%
  (class pre-chain%
    (inherit-field issuer-chain)
    (init-field errors)
    (super-new)
    (define/override (get-errors) errors)))

;; ============================================================

(define serializable-chain<%>
  (interface*
   ()
   ([prop:serializable
     (make-serialize-info (lambda (c) (send c -serialize))
                          #'deserialize-info:certificate-chain%
                          #f
                          (or (current-load-relative-directory)
                              (current-directory)))])))

(define deserialize-info:certificate-chain%
  (make-deserialize-info
   (lambda (issuer-chain cert)
     (cond [issuer-chain (send issuer-chain extend-chain cert)]
           [else (make-anchor-chain cert)]))
   (lambda () (error 'deserialize-certificate-chain "cycles not allowed"))))

;; ============================================================

(define certificate-chain%
  (class* pre-chain% (-certificate-chain<%> writable<%> serializable-chain<%>)
    (inherit-field issuer-chain cert)
    (inherit get-certificate
             get-anchor
             get-validity-seconds
             get-issuer-or-self
             get-subject
             get-subject-alt-names
             ok-extended-key-usage?
             get-eku-chain
             check-as-final
             check-security-level
             check-validity-period)
    (super-new)

    (define/public (custom-write out)
      (fprintf out "#<certificate-chain: ~a>"
               (Name->string (send (get-certificate) get-subject))))
    (define/public (custom-display out)
      (custom-write out))

    (define/public (-serialize)
      (vector issuer-chain cert))

    ;; trusted? : Store/#f Seconds Seconds -> Boolean
    (define/public (trusted? store [from-time (current-seconds)] [to-time from-time])
      (null? (check-trust store from-time to-time)))

    ;; check-trust : Store/#f Seconds Seconds -> ErrorList
    (define/public (check-trust store [from-time (current-seconds)] [to-time from-time]
                                #:security-level [security-level 0])
      (append (cond [(not store) '()]
                    [(send store trust? (get-anchor)) '()]
                    [else '((0 . anchor:not-trusted))])
              (check-security-level security-level)
              (check-as-final)
              (check-validity-period from-time to-time)))

    ;; ok-validity-period? : Seconds [Seconds] -> Boolean
    (define/public (ok-validity-period? [from-time (current-seconds)] [to-time from-time])
      (null? (check-validity-period from-time to-time)))

    ;; ----------------------------------------
    ;; Checking suitability for a purpose

    (define/public (suitable-for-ocsp-signing? for-ca-chain)
      ;; RFC 6960 4.2.2.2 says "a certificate's issuer MUST do one of the
      ;; following: sign the OCSP responses itself, or explicitly designate this
      ;; authority to another entity".
      ;; - What does "itself" mean? Same certificate > same public key >> same
      ;;   subject Name. Let's use "same public key".
      ;; - Likewise, how to check delegation? Check signed by "same public key"
      ;;   as original issuer.
      (define for-ca-cert (send for-ca-chain get-certificate))
      (or (and (send cert is-CA?)
               (send cert has-same-public-key? for-ca-cert))
          ;; The id-kp-OCSPSigning EKU check is shallow; it should only appear
          ;; in the responder certificate. One reason: Including the EKU in
          ;; ancestor CA certificates would allow every subordinate CA to sign
          ;; OCSP responses for its issuer CAs.
          (and (eq? (send cert get-eku id-kp-OCSPSigning) 'yes)
               (send (get-issuer-or-self) has-same-public-key? for-ca-cert))))

    (define/public (suitable-for-tls-server? host)
      (null? (check-suitable-for-tls-server host)))

    (define/public (check-suitable-for-tls-server host)
      ;; FIXME: add option to accept anyExtendedKeyUsage?
      ;; FIXME: add option to use subject common name?
      ;; FIXME: add security level check?
      ;; FIXME: add validity period check?
      ;; References:
      ;; - https://tools.ietf.org/html/rfc5246#section-7.4.2
      ;; - https://tools.ietf.org/html/rfc5280#section-4.2.1.12
      ;; - CA/B Baseline Requirements (Section 7.1 Certificate Profile)
      (define USE-CN? #f)
      (append (cond [(for/or ([use (in-list tls-key-usages)]) (ok-key-usage? use #t)) '()]
                    [else '(tls:missing-key-usage)])
              (cond [(ok-extended-key-usage? id-kp-serverAuth #f) '()]
                    [else '(tls:missing-serverAuth-eku)])
              (cond [(or (not host)
                         (for/or ([pattern (in-list (get-subject-alt-names 'dNSName))])
                           (host-matches? host pattern))
                         (and USE-CN?
                              (for/or ([cn (in-list (send cert get-subject-common-names))])
                                (and cn (host-matches? host cn)))))
                     '()]
                    [else '(tls:host-mismatch)])))

    (define/public (suitable-for-tls-client? name)
      (null? (check-suitable-for-tls-client name)))

    (define/public (check-suitable-for-tls-client name)
      (append (cond [(for/or ([use (in-list tls-key-usages)]) (ok-key-usage? use #t)) '()]
                    [else '(tls:missing-key-usage)])
              (cond [(ok-extended-key-usage? id-kp-clientAuth #f) '()]
                    [else '(tls:missing-clientAuth-eku)])
              (cond [(or (not name)
                         (GeneralName-equal? name (list 'directoryName (get-subject)))
                         (for/or ([altname (in-list (get-subject-alt-names #f))])
                           (GeneralName-equal? name altname)))
                     '()]
                    [else '(tls:name-mismatch)])))

    (define/public (ok-key-usage? use [default #f]) (send cert ok-key-usage? use default))
    ))

;; tls-key-usages is approximation; actually depends on TLS cipher negotiated
(define tls-key-usages '(digitalSignature keyEncipherment keyAgreement))
