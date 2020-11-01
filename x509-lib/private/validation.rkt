#lang racket/base
(require racket/match
         racket/class
         racket/list
         racket/string
         racket/date
         crypto
         crypto/pem
         asn1
         "interfaces.rkt"
         "x509-asn1.rkt"
         "cert-info.rkt"
         "stringprep.rkt"
         (only-in crypto/private/common/asn1 relation-ref))
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

(struct exn:x509 exn:fail () #:transparent)
(struct exn:x509:certificate exn:x509 (errors) #:transparent)
(struct exn:x509:chain exn:x509 (errors) #:transparent)

;; An ErrorList is a list of "error description" values.
;; The empty list means no errors were detected.

;; ============================================================

(define certificate%
  (class* certificate-data% (certificate<%>)
    (init [check-who 'certificate])
    (inherit get-der
             get-cert-signature-alg
             get-cert-signature-bytes

             get-version
             get-serial-number
             get-signature-alg
             get-issuer
             get-validity
             get-subject
             get-spki
             get-issuer-unique-id
             get-subject-unique-id
             get-extensions

             is-CA?
             is-CRL-issuer?
             is-self-issued?
             is-self-signed?
             get-key-uses

             get-extension
             get-extension-value

             get-name-constraints
             get-subject-alt-name
             get-validity-seconds)
    (super-new)

    ;; ----------------------------------------

    (when check-who
      (let ([errors (check)])
        (unless (null? errors)
          (raise (exn:x509:certificate
                  (format "~s: invalid X509 certificate\n  errors: ~s" check-who errors)
                  (current-continuation-marks)
                  errors)))))

    ;; ----------------------------------------

    (define/public (ok-signature? issuer-pk)
      (define vcert (bytes->asn1 Certificate-for-verify-sig (get-der)))
      (define tbs-der (hash-ref vcert 'tbsCertificate))
      (define alg (hash-ref vcert 'signatureAlgorithm))
      (define alg-oid (hash-ref alg 'algorithm))
      ;; FIXME: check issuer-pk is appropriate for alg
      (unless (eq? #f (hash-ref alg 'parameters #f))
        (error 'verify-signature "internal error: parameters not supported"))
      (define di (relation-ref SIGNING 'oid (hash-ref alg 'algorithm) 'digest))
      (digest/verify issuer-pk di tbs-der (get-cert-signature-bytes)))

    (define/public (get-pk) (datum->pk-key (get-spki) 'SubjectPublicKeyInfo))

    ;; check : -> ErrorList
    ;; Checks that the certificate is well-formed, without regard for other
    ;; certificates in the chain or any intended purpose. In particular:
    ;; - The signature is not verified!
    ;; - The validity period is not checked.
    ;; - The name, allowed uses, etc are not checked against an intended purpose.
    ;; An error symbol should read as a true statement about the certificate
    ;; that points out a fault, rather than reading as a desired property that
    ;; the certificate fails to hold.
    (define/public (check)
      (define errors null) ;; ErrorList, mutated
      (define (bad! x)        (set! errors (cons x errors)))
      (define (bad/ca! x)     (when #t (bad! x)))
      (define (bad/should! x) (when #f (bad! x)))
      ;; 4.1.1.2
      (unless (equal? (get-cert-signature-alg) (get-signature-alg))
        (bad! 'signature-algorithm:mismatch))
      ;; 4.1.1.3
      ;; -- 'signature-valid, checked later
      ;; 4.1.2.1    -- note: v3 = 2, etc
      (cond [(pair? (get-extensions))
             (unless (= (get-version) v3)
               (bad! 'version:v3-required-when-extensions))]
            [(or (get-issuer-unique-id) (get-subject-unique-id))
             (unless (= (get-version) v2)
               (bad/should! 'version:v3-preferred-when-unique-id))
             (unless (member (get-version) (list v2 v3))
               (bad! 'version:v2/v3-required-when-unique-id))]
            [else
             (unless (= (get-version) v1)
               (bad/should! 'version:v1-preferred-when-basic))
             (unless (member (get-version) (list v1 v2 v3))
               (bad! 'version:v1/v2/v3-required))])
      ;; 4.1.2.2
      (unless (positive? (get-serial-number)) (bad/ca! 'serial-number:not-positive))
      ;; -- 'serial-number-unique, cannot check
      ;; 4.1.2.3
      ;; -- 'signature-algs-same, checked in 4.1.1.2
      ;; 4.1.2.4 Issuer
      (when (Name-empty? (get-issuer)) (bad! 'issuer:empty))
      ;; 4.1.2.5 Validity
      ;; -- 'validity-encoding-by-year (CA-MUST), not checked because client MUST accept both
      ;; -- 'validity-time, checked later
      ;; 4.1.2.5.{1,2}
      (match (get-validity)
        [(hash-table ['notBefore ok-start] ['notAfter ok-end])
         (unless (wf-time? ok-start) (bad! 'validity:start-not-well-formed))
         (unless (wf-time? ok-end) (bad! 'validity:end-not-well-formed))])
      ;; 4.1.2.6 Subject
      (when (or (is-CA?) (is-CRL-issuer?))
        (when (Name-empty? (get-subject))
          (bad! 'subject:empty-but-CA/CRL-issuer)))
      (when (Name-empty? (get-subject))
        (cond [(get-extension id-ce-subjectAltName)
               (lambda (ext)
                 (unless (extension-critical? ext)
                   (bad! 'subject:empty-with-noncritical-subjectAltName)))]
              [else
               (bad! 'subject:empty-with-missing-subjectAltName)]))
      ;; ----------------------------------------
      ;; 4.2 Certificate Extensions
      (unless (unique-by-key? (get-extensions) extension-id)
        (bad! 'extensions:not-unique))
      ;; constraints on extension that must be present
      (begin
        ;; 4.2.1.1 Authority Key Identifier
        (unless (and (is-CA?) (is-self-signed?))
          (unless (get-extension id-ce-authorityKeyIdentifier)
            ;; FIXME: check
            (bad/should! 'authority-key-id:missing)))
        ;; 4.2.1.2 Subject Key Identifier
        (unless (get-extension id-ce-subjectKeyIdentifier)
          (bad/should! 'subject-key-id:missing))
        ;; 4.2.1.3 Key Usage
        (when (is-CA?)
          (unless (get-extension id-ce-keyUsage)
            ;; ??? "Conforming CAs MUST include this extension in certificates
            ;; that contain public keys that are used to validate digital
            ;; signatures on other public key certificates or CRLs." Are there
            ;; other kinds of CAs?!
            (void) #;(bad/ca! 'key-usage:missing-but-CA)))
        (void))
      ;; constraints on extensions when present
      (for ([ext (in-list (get-extensions))])
        (define ext-id (extension-id ext))
        (define critical? (extension-critical? ext))
        (cond
          ;; 4.2.1.1 Authority Key Identifier
          [(equal? ext-id id-ce-authorityKeyIdentifier)
           (unless (not critical?) (bad/ca! 'authority-key-id:critical))]
          ;; 4.2.1.2 Subject Key Identifier
          [(equal? ext-id id-ce-subjectKeyIdentifier)
           (unless (not critical?) (bad/ca! 'subject-key-id:critical))]
          ;; 4.2.1.3 Key Usage
          [(equal? ext-id id-ce-keyUsage)
           (unless critical?
             (bad/should! 'key-usage:not-critical))
           (define bits (extension-value ext))
           (when (memq 'keyCertSign bits)
             (unless (is-CA?) (bad! 'key-usage:keyCertSign-but-not-CA)))
           (unless (pair? bits) (bad! 'key-usage:empty))]
          ;; 4.2.1.4 Certificate Policies
          [(equal? ext-id id-ce-certificatePolicies)
           (define policies (extension-value ext))
           (unless (unique-by-key? policies policy-id)
             (bad! 'policies:not-unique))
           (when (extension-critical? ext)
             (bad! 'policies:critical-but-unsupported))]
          ;; 4.2.1.5 Policy Mappings
          [(equal? ext-id id-ce-policyMappings)
           (when critical?
             (bad! 'policy-mappings:critical-but-unsupported))]
          ;; 4.2.1.6 Subject Alternative Name
          [(equal? ext-id id-ce-subjectAltName)
           ;; These are interpreted elsewhere, and we don't check wf here.
           (void)]
          ;; 4.2.1.7 Issuer Alternative Name
          [(equal? ext-id id-ce-issuerAltName)
           (when critical?
             (bad/should! 'issuer-alt-name:critical))]
          ;; 4.2.1.8 Subjct Directory Attributes
          [(equal? ext-id id-ce-subjectDirectoryAttributes)
           (when critical?
             (bad/ca! 'subject-directory-attributes:critical))]
          ;; 4.2.1.9 Basic Constraints
          [(equal? ext-id id-ce-basicConstraints)
           (when (memq 'keyCertSign (get-key-uses))
             (unless critical?
               (bad/ca! 'basic-constraints:not-critical-but-keyCertSign)))
           (when (hash-ref (extension-value ext) 'pathLenConstraint #f)
             (unless (and (is-CA?) (memq 'keyCertSign (get-key-uses)))
               (bad! 'basic-constraints:pathLenConstraint-but-not-CA)))]
          ;; 4.2.1.10 Name Constraints
          [(equal? ext-id id-ce-nameConstraints)
           (define ncs (extension-value ext))
           (unless (or (pair? (hash-ref ncs 'permittedSubtrees null))
                       (pair? (hash-ref ncs 'excludedSubtrees null)))
             (bad! 'name-constraints:empty))
           (for/first ([t (in-list (append (hash-ref ncs 'permittedSubtrees null)
                                           (hash-ref ncs 'excludedSubtrees null)))]
                       #:when (or (not (zero? (hash-ref t 'minimum 0)))
                                  (hash-has-key? t 'maximum)))
             (bad! 'name-constraints:non-default-min/max))
           ;; These are interpreted in chain validation.
           (unless (is-CA?) (bad! 'name-constraints:present-but-not-CA))
           ;; FIXME: ???
           #;(unless (not critical?) (bad! 'name-constraints:critical-but-unsupported))]
          ;; 4.2.1.11 Policy Constraints
          [(equal? ext-id id-ce-policyConstraints)
           ;; FIXME!
           (unless (not critical?) (bad! 'policy-constraints:critical-but-unsupported))]
          ;; 4.2.1.12 Extended Key Usage
          [(equal? ext-id id-ce-extKeyUsage)
           ;; FIXME!
           (unless (not critical?) (bad! 'extended-key-usage:critical-but-unsupported))]
          ;; 4.2.1.13 CRL Distribution points
          [(equal? ext-id id-ce-cRLDistributionPoints)
           (unless (not critical?) (bad! 'crl-distribution-points:critical-but-unsupported))]
          ;; 4.2.1.14 Inhibit anyPolicy
          [(equal? ext-id id-ce-inhibitAnyPolicy)
           (unless (not critical?) (bad! 'inhibit-anyPolicy:critical-but-unsupported))]
          ;; 4.2.1.15 Freshest CRL
          [(equal? ext-id id-ce-freshestCRL)
           (unless (not critical?) (bad! 'freshest-crl:critical-but-unsupported))]
          ;; Other: ignore unless critical
          [else
           (unless (not critical?) (bad! 'unknown-extension:critical-but-unsupported))]))
      errors)

    (define/public (ok-key-usage? uses)
      (define key-uses (get-key-uses))
      (and (for/and ([use (in-list uses)]) (memq use key-uses)) #t))

    ;; ============================================================

    ;; check-link-in-chain : Nat Certificate Validation Boolean -> Void
    ;; Pushes errors to the given validation% object.
    (define/public (check-link-in-chain index issuer vi final-in-path?)
      (define (add-error what) (send vi add-error (cons index what)))
      ;; 6.1.3
      (begin
        ;; 6.1.3 (a)(1) verify signature
        (unless (ok-signature? (send issuer get-pk))
          (add-error 'bad-signature))
        ;; 6.1.3 (a)(2) currently valid; checked in check-valid-period
        (void)
        ;; 6.1.3 (a)(3) (not revoked)
        (void 'CRL-UNSUPPORTED)
        ;; 6.1.3 (a)(4) issuer
        (unless (Name-equal? (get-issuer) (send issuer get-subject))
          (add-error 'issuer-name-mismatch))
        ;; 6.1.3 (b,c) check name constraints
        (unless (and (is-self-issued?) (not final-in-path?))
          (unless (send vi name-constraints-accept? (list 'directoryName (get-subject)))
            (add-error 'name-constraints:subject-rejected))
          ;; FIXME: check email address in (get-subject) ???
          (for ([san (in-list (get-subject-alt-name))])
            (unless (send vi name-constraints-accept? san)
              (add-error 'name-constraints:subjectAltName-rejected))))
        ;; 6.1.3 (d-f) process policies; set/check valid-policy-tree, explicit-policy
        (void 'POLICIES-UNSUPPORTED))
      ;; 6.1.4
      (unless final-in-path?
        ;; 6.1.4 (a-b) policy-mappings, policies, ...
        (void 'POLICIES-UNSUPPORTED)
        ;; 6.1.4 (c-f) handled by get-pk method instead
        (void 'OK)
        ;; 6.1.4 (g) name constraints
        (send vi add-name-constraints index (get-name-constraints))
        ;; 6.1.4 (h, l) decrement counters
        (unless (is-self-issued?)
          (send vi decrement-counters))
        ;; 6.1.4 (i, j) policy-mapping, inhibit-anypolicy, ...
        (void 'POLICIES-UNSUPPORTED)
        ;; 6.1.4 (k) check CA (reject if no basicConstraints extension)
        (unless (is-CA?) (add-error 'intermediate:not-CA))
        ;; 6.1.4 (m)
        (let* ([ext (get-extension id-ce-basicConstraints)]
               [plen (and ext (hash-ref (extension-value ext) 'pathLenConstraint #f))])
          (when plen (send vi set-max-path-length plen)))
        ;; 6.1.4 (n)
        (let ([key-uses (get-key-uses)])
          (when (pair? key-uses)
            (unless (memq 'keyCertSign key-uses)
              (add-error 'intermediate:missing-keyCertSign))))
        ;; 6.1.4 (o) process other critical extensions: errors gathered in construction
        (void 'DONE-DURING-CONSTRUCTION))
      ;; 6.1.5
      (when final-in-path?
        ;; 6.1.5 (a,b) explicit-policy, policies
        (void 'POLICIES-UNSUPPORTED)
        ;; 6.1.5 (c-e) handled by get-pk method instead
        (void 'OK)
        ;; 6.1.5 (f) process other critical extensions: errors gathered in construction
        (void 'DONE-DURING-CONSTRUCTION)
        ;; 6.1.5 (g) policies ...
        (void 'POLICIES-UNSUPPORTED))
      (void))

    ;; check-valid-period : Nat Validation Seconds Seconds -> Void
    ;; Pushes errors to the given validation% object.
    (define/public (check-valid-period index vi from-time to-time)
      ;; 6.1.3 (a)(2) currently valid
      (match-define (list ok-start ok-end) (get-validity-seconds))
      (send vi intersect-valid-period ok-start ok-end)
      (unless (<= ok-start from-time to-time ok-end)
        (send vi add-error (cons index 'bad-validity-period))))
    ))

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
  (class* object% (certificate-chain<%>)
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

;; ============================================================

;; ParsedNameConstraints = (Listof NameConstraintLayer)
;; NameConstraintLayer = (nclayer (U 'permit 'exclude) Nat (Listof GeneralName))

;; If a layer contains multiple entries for a given name-type, it *matches* (ie,
;; permits or excludes, depending on mode) if any of the patterns match. (FIXME:
;; double-check this is intended behavior)

;; If a layer contains no entries for a given name-type, it *allows* all names
;; of that name type (whether the mode is 'permit or 'exclude).

(struct nclayer (mode index gnames) #:prefab)

(define (extend-name-constraints cs index ncs)
  (define (add base mode sts)
    (cons (nclayer mode index (map (lambda (st) (hash-ref st 'base)) sts)) base))
  (let* ([cs (cond [(hash-ref ncs 'permittedSubtrees #f)
                    => (lambda (sts) (add cs 'permit sts))]
                   [else cs])]
         [cs (cond [(hash-ref ncs 'excludedSubtrees #f)
                      => (lambda (sts) (add cs 'exclude sts))]
                     [else cs])])
    cs))

;; Note: this checks that a specific name satisfies all constraint layers. It
;; does not check that an intermediate certificate's constraints are narrower
;; than the existing constraints.

(define (name-constraints-name-ok? cs general-name)
  (match-define (list (? symbol? name-type) name) general-name)
  (define (layer-name-ok? layer)
    (match-define (nclayer mode index pattern) layer)
    (define relevant (filter (lambda (gn) (eq? name-type (car gn))) pattern))
    (cond [(null? relevant) #t]
          [(eq? mode 'permit)
           (ormap (constraint-matches? #f) relevant)]
          [(eq? mode 'exclude)
           (not (ormap (constraint-matches? #t) relevant))]))
  (define ((constraint-matches? result-for-unsupported) gn)
    (match-define (list (== name-type) pattern) gn)
    (case name-type
      [(rfc822Name) ;; name : IA5String
       ;; FIXME: this assumes that name is a valid rfc822 email address (??)
       (cond [(regexp-match? #rx"@" pattern)
              ;; pattern is address => must match exactly
              (string-ci=? name pattern)]
             [(regexp-match #rx"^[.]" pattern)
              ;; pattern is domain => must match extension
              (string-suffix-ci? name pattern)]
             [else ;; host => host must match exactly, with mailbox prefix
              (string-suffix-ci? name (string-append "@" pattern))])]
      [(dNSName) ;; name : IA5String
       (cond [(regexp-match? #rx"^[.]" pattern)
              ;; This form does not appear in RFC 5280 for DNS constraints, but
              ;; it does appear in multiple HOWTOs around the internet.
              (string-suffix-ci? name pattern)]
             [else
              (or (string-ci=? name pattern)
                  (string-suffix-ci? name (string-append "." pattern)))])]
      [(directoryName) ;; name : Name
       (Name-prefix? pattern name)]
      [(uniformResourceIdentifier) ;; name : IA5String
       result-for-unsupported]
      [(iPAddress) ;; name : OCTET-STRING
       (define iplen (bytes-length name))
       (cond [(= (bytes-length pattern) (* 2 iplen))
              (for/and ([ip-b (in-bytes name)]
                        [ipp-b (in-bytes pattern 0)]
                        [mask-b (in-bytes pattern iplen)])
                (= ipp-b (bitwise-and ip-b mask-b)))]
             [else #f])]
      ;; otherName
      ;; x400Address
      ;; ediPartyName
      ;; registeredID
      [else result-for-unsupported]))
  (andmap layer-name-ok? cs))

;; (define (uri-extract-host uri)
;;   ;; Reference: https://tools.ietf.org/html/rfc3986#section-3
;;   ;; URIwHost ::= scheme "://" authority path-abempty [ "?" query ]["#" fragment]
;;   ;; authority ::= [userinfo "@"] host [":" port]
;;   (match uri
;;     [(regexp #rx"^([a-zA-Z][a-zA-Z0-9]*)://([^?#/]*)"
;;              (list _ _ (regexp #rx"^(?:[^@]*@)?([^:]*)(?:[:][0-9]*)?$"
;;                                (list _ host))))
;;      (uri-decode host)]
;;     [_ #f]))

(define (string-suffix-ci? s suffix)
  (define slen (string-length s))
  (define suffixlen (string-length suffix))
  (and (<= suffixlen slen)
       (string-ci=? (substring s (- slen suffixlen))
                    suffix)))

;; ============================================================

;; read-pem-certs : InputPort -> (Listof Bytes)
(define (read-pem-certs in)
  (for/list ([v (in-port (lambda (in) (read-pem in #:only '(#"CERTIFICATE"))) in)])
    (cdr v)))

;; read-certs : Path -> (Listof certificate%)
(define (read-certs file)
  (define ders (call-with-input-file file read-pem-certs))
  (map (lambda (der) (new certificate% (der der))) ders))

;; ============================================================

(define x509-store%
  (class* object% (x509-store<%>)
    (init-field [trusted-h '#hash()]
                [cert-h    '#hash()]
                [stores null])
    (super-new)

    (define/public (trust? cert)
      (or (hash-ref trusted-h (send cert get-der) #f)
          (for/or ([store (in-list stores)]) (send store trust? cert))))

    (define/public (lookup-by-subject dn)
      (apply append
             (for/list ([cert (in-hash-keys cert-h)]
                        #:when (Name-equal? dn (send cert get-subject)))
               cert)
             (for/list ([store (in-list stores)]) (send store lookup-by-subject dn))))

    (define/public (add #:untrusted-certs [untrusted-certs null]
                        #:trusted-certs [trusted-certs null]
                        #:stores [new-stores null])
      (define ((mkcons v) vs) (cons v vs))
      (define cert-h*
        (for*/fold ([h cert-h])
                   ([certs (in-list (list untrusted-certs trusted-certs))]
                    [cert (in-list certs)])
          (hash-set h cert #t)))
      (define trusted-h*
        (for/fold ([h trusted-h])
                  ([cert (in-list trusted-certs)])
          (hash-set h (send cert get-der) #t)))
      (new this% (trusted-h trusted-h*) (cert-h cert-h*)
           (stores (append stores new-stores))))

    (define/public (add-trusted-from-pem-file pem-file)
      (add #:trusted-certs (read-certs pem-file)))
    (define/public (add-trusted-from-openssl-directory dir)
      (add #:stores (list (new x509-lookup:openssl-trusted-directory% (dir dir)))))

    ;; ----------------------------------------

    ;; build-chain : Cert (Listof Cert) -> CertificateChain
    (define/public (build-chain end-cert [other-untrusted-certs null]
                                [valid-time (current-seconds)]
                                #:who [who 'build-chain])
      (car (build-chains end-cert other-untrusted-certs valid-time #:who who)))

    ;; build-chains : Cert (Listof Cert) -> (Listof CertificateChain)
    (define/public (build-chains end-cert [other-untrusted-certs null]
                                 [valid-time (current-seconds)]
                                 #:empty-ok? [empty-ok? #f]
                                 #:who [who 'build-chains])
      (define store* (add #:untrusted-certs other-untrusted-certs))
      (define candidates (send store* build-candidate-chains end-cert))
      (unless (or (pair? candidates) empty-ok?)
        (raise-incomplete-chain-error who end-cert))
      (check-chains candidates valid-time #:empty-ok? empty-ok? #:who who))

    ;; build-candidate-chains : Cert -> (Listof (Listof Cert))
    (define/public (build-candidate-chains end-cert)
      (define (loop chains)
        (cond [(pair? chains)
               (define chains* (append* (map loop1 chains)))
               (define-values (complete incomplete)
                 (partition (lambda (chain) (trust? (car chain))) chains*))
               (append complete (loop incomplete))]
              [else null]))
      (define (loop1 chain)
        (define issuer-name (send (car chain) get-issuer))
        (for/list ([issuer-cert (in-list (remove-duplicates (lookup-by-subject issuer-name)))]
                   #:when (not (member issuer-cert chain)))
          (cons issuer-cert chain)))
      (loop (list (list end-cert))))

    ;; check-chain : (Listof Cert) -> CertificateChain
    (define/public (check-chain candidate [valid-time (current-seconds)]
                                #:who [who 'check-chain])
      (car (check-chains (list candidate) valid-time #:empty-ok? #f #:who who)))

    ;; check-chains : (Listof (Listof Cert)) -> (Listof CertificateChain)
    ;; Discards invalid chains, returns certificate-chain% objects for valid.
    (define/public (check-chains candidates [valid-time (current-seconds)]
                                 #:empty-ok? [empty-ok? #f]
                                 #:who [who 'check-chains])
      (define cv-chains
        (fault-filter candidates empty-ok?
                      (lambda (candidate)
                        (check-candidate-chain candidate valid-time))
                      (lambda (candidate errs)
                        (raise-invalid-chain-error who candidate errs))))
      (define trusted-chains
        (fault-filter cv-chains empty-ok?
                      (lambda (chain)
                        (define errs (send chain check-trust this valid-time))
                        (if (null? errs) (values chain null) (values #f errs)))
                      (lambda (chain errs)
                        (raise-invalid-chain-error who chain errs))))
      trusted-chains)
    ))

(define empty-x509-store (new x509-store%))

(define (raise-invalid-chain-error who end-cert errs)
  (let/ec escape
    (define msg (format "~s: chain validation failed\n  errors: ~e" who errs))
    (raise (exn:x509:chain msg (continuation-marks escape) errs))))
(define (raise-incomplete-chain-error who end-cert)
  (let/ec escape
    (define msg (format "~s: failed to build complete chain\n  end certificate: ~e" who end-cert))
    (raise (exn:x509:chain msg (continuation-marks escape) '(incomplete)))))

;; fault-filter : (Listof X) Bool (X -> (values Y/#f List)) (X List -> Z)
;;             -> (Listof Y) or Z
(define (fault-filter xs empty-ok? get-y/errs handle-errs)
  (define-values (ok-ys errss)
    (for/lists (ys errss #:result (values (filter values ys) errss))
               ([x (in-list xs)])
      (get-y/errs x)))
  (cond [(or (pair? ok-ys) empty-ok?) ok-ys]
        [(pair? errss) (handle-errs (car xs) (car errss))]
        [else (error 'fault-filter "internal error: given empty list")]))

;; ----------------------------------------

(define x509-lookup:openssl-trusted-directory%
  (class* object% (x509-lookup<%>)
    (init-field dir)
    (super-new)

    ;; trusted-cache : WeakHasheq[Certificate => #t]
    ;; FIXME: add timeout to cache?
    (define trusted-cache (make-weak-hasheq))

    (define/public (trust? cert)
      (or (hash-ref trusted-cache cert #f)
          (for/or ([trusted (in-list (lookup-by-subject (send cert get-subject)))])
            (send trusted equal-to cert))))

    (define/public (lookup-by-subject dn)
      (define (padto n s) (string-append (make-string (- n (string-length s)) #\0) s))
      (define base (padto 8 (number->string (dn-hash (asn1->bytes Name dn)) 16)))
      (let loop ([i 0])
        (define file (build-path dir (format "~a.~a" base i)))
        (cond [(file-exists? file)
               (define cert (read-cert-from-file file))
               (cond [(and cert (Name-equal? dn (send cert get-subject)))
                      (hash-set! trusted-cache cert #t)
                      (cons cert (loop (add1 i)))]
                     [else (loop (add1 i))])]
              [else null])))

    (define/private (dn-hash dn-der)
      (local-require (submod "." openssl-x509))
      (NAME-hash dn-der))

    ;; FIXME: cache reads?

    (define/private (read-cert-from-file file)
      (match (call-with-input-file* file read-pem-certs)
        [(list der) (new certificate% (der der))]
        [_ (begin0 #f (log-x509-error "bad certificate PEM file: ~e" file))]))
    ))

(module openssl-x509 racket/base
  (require ffi/unsafe
           ffi/unsafe/define
           ffi/unsafe/alloc
           openssl/libssl)
  (provide (protect-out (all-defined-out)))
  (define-ffi-definer define-ssl libssl
    #:default-make-fail make-not-available)
  (define-cpointer-type _X509_NAME)
  (define-ssl X509_NAME_free (_fun _X509_NAME -> _void)
    #:wrap (deallocator))
  (define-ssl d2i_X509_NAME
    (_fun (_pointer = #f) (_ptr i _pointer) _long -> _X509_NAME/null)
    #:wrap (allocator X509_NAME_free))
  (define-ssl X509_NAME_hash (_fun _X509_NAME -> _long))
  (define (NAME-hash dn-der)
    (define dn (d2i_X509_NAME dn-der (bytes-length dn-der)))
    (begin0 (X509_NAME_hash dn) (X509_NAME_free dn))))
