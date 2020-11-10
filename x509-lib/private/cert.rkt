#lang racket/base
(require racket/match
         racket/class
         crypto
         asn1
         "interfaces.rkt"
         "asn1.rkt"
         "cert-data.rkt"
         (only-in crypto/private/common/asn1 relation-ref))
(provide (all-defined-out))

;; References:
;; - RFC 5280 (https://tools.ietf.org/html/rfc5280)
;; - RFC 6818 (general updates) (https://tools.ietf.org/html/rfc6818)
;; - RFC 8398 and 8399 (Internationalization) (https://tools.ietf.org/html/rfc8398,
;;   https://tools.ietf.org/html/rfc8399)

;; FIXME: asn1 parser returns mutable bytes,strings?

;; FIXME: need mechanism for disallowing obsolete algorithms (eg, 1024-bit RSA / DSA)

(define TLS-USE-COMMON-NAME? #f)

;; ============================================================

(define certificate%
  (class* certificate-data% (-certificate<%>)
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
             get-subject-common-names

             is-CA?
             is-CRL-issuer?
             is-self-issued?
             is-self-signed?
             get-key-uses
             ok-key-use?
             get-extended-key-uses
             ok-extended-key-use?

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

    (when #f ;; debug: log certificate warnings?
      (let ([warnings (check #t)])
        (when (pair? warnings)
          (log-error "warnings for ~e: ~s" this warnings))))

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

    (define/public (get-public-key) (datum->pk-key (get-spki) 'SubjectPublicKeyInfo))

    ;; check : -> ErrorList
    ;; Checks that the certificate is well-formed, without regard for other
    ;; certificates in the chain or any intended purpose. In particular:
    ;; - The signature is not verified!
    ;; - The validity period is not checked.
    ;; - The name, allowed uses, etc are not checked against an intended purpose.
    ;; An error symbol should read as a true statement about the certificate
    ;; that points out a fault, rather than reading as a desired property that
    ;; the certificate fails to hold.
    (define/public (check [include-warnings? #f])
      (define errors null) ;; ErrorList, mutated
      (define (add-error! x)  (set! errors (cons x errors)))
      ;; bad!         -- used for "MUST" requirements that are enforced
      ;; warn!        -- used for requirements that are enforced only when include-warnings?
      ;; bad/should!  -- used for "SHOULD" requirements (not enforced!)
      ;; bad/ca-must! -- used for "conforming CA MUST" requirements (not enforced!)
      (define (bad! x)         (add-error! x))
      (define (warn! x)        (when include-warnings? (add-error! x)))
      (define (bad/should! x)  (warn! x))
      (define (bad/ca-must! x) (warn! x))
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
      (unless (positive? (get-serial-number))
        (bad/ca-must! 'serial-number:not-positive))
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
                   (bad! 'subject:empty-but-noncritical-subjectAltName)))]
              [else
               (bad! 'subject:empty-but-missing-subjectAltName)]))
      ;; 4.1.2.8 Unique Identifiers
      (when (or (get-issuer-unique-id) (get-subject-unique-id))
        (bad/ca-must! 'unique-id:present))
      ;; ----------------------------------------
      ;; 4.2 Certificate Extensions
      (unless (unique-by-key? (get-extensions) extension-id)
        (bad! 'extensions:not-unique))
      ;; constraints that require extensions to be present
      (begin
        ;; 4.2.1.1 Authority Key Identifier
        (unless (and (is-CA?) (is-self-signed?))
          (unless (get-extension id-ce-authorityKeyIdentifier)
            (bad/ca-must! 'authority-key-id:missing)))
        ;; 4.2.1.2 Subject Key Identifier
        (when (is-CA?)
          (unless (get-extension id-ce-subjectKeyIdentifier)
            ;; FIXME: re-check
            (bad/ca-must! 'subject-key-id:missing-but-CA)))
        ;; 4.2.1.3 Key Usage
        (when (is-CA?)
          (unless (get-extension id-ce-keyUsage)
            (bad/ca-must! 'key-usage:missing-but-CA)))
        (void))
      ;; constraints on extensions when present
      (for ([ext (in-list (get-extensions))])
        (define ext-id (extension-id ext))
        (define critical? (extension-critical? ext))
        (cond
          ;; 4.2.1.1 Authority Key Identifier
          [(equal? ext-id id-ce-authorityKeyIdentifier)
           (when critical? (bad/ca-must! 'authority-key-id:critical))]
          ;; 4.2.1.2 Subject Key Identifier
          [(equal? ext-id id-ce-subjectKeyIdentifier)
           (when critical? (bad/ca-must! 'subject-key-id:critical))]
          ;; 4.2.1.3 Key Usage
          [(equal? ext-id id-ce-keyUsage)
           (when (not critical?)
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
             (bad/ca-must! 'subject-directory-attributes:critical))]
          ;; 4.2.1.9 Basic Constraints
          [(equal? ext-id id-ce-basicConstraints)
           (when (memq 'keyCertSign (get-key-uses))
             (unless critical?
               (bad/ca-must! 'basic-constraints:not-critical-but-keyCertSign)))
           (when (hash-ref (extension-value ext) 'pathLenConstraint #f)
             (unless (and (is-CA?) (memq 'keyCertSign (get-key-uses)))
               (bad! 'basic-constraints:pathLenConstraint-but-not-keyCertSign)))]
          ;; 4.2.1.10 Name Constraints
          [(equal? ext-id id-ce-nameConstraints)
           (define ncs (extension-value ext))
           (unless (or (pair? (hash-ref ncs 'permittedSubtrees null))
                       (pair? (hash-ref ncs 'excludedSubtrees null)))
             (bad/ca-must! 'name-constraints:empty))
           (for/first ([t (in-list (append (hash-ref ncs 'permittedSubtrees null)
                                           (hash-ref ncs 'excludedSubtrees null)))]
                       #:when (or (not (zero? (hash-ref t 'minimum 0)))
                                  (hash-has-key? t 'maximum)))
             (bad! 'name-constraints:non-default-min/max))
           ;; These are interpreted in chain validation.
           (unless (is-CA?) (bad! 'name-constraints:present-but-not-CA))]
          ;; 4.2.1.11 Policy Constraints
          [(equal? ext-id id-ce-policyConstraints)
           ;; FIXME!
           (when critical? (bad! 'policy-constraints:critical-but-unsupported))]
          ;; 4.2.1.12 Extended Key Usage
          [(equal? ext-id id-ce-extKeyUsage)
           (when (member anyExtendedKeyUsage (get-extended-key-uses))
             (when critical?
               (bad/should! 'extended-key-usage:critical-but-anyExtendedKeyUse)))]
          ;; 4.2.1.13 CRL Distribution points
          [(equal? ext-id id-ce-cRLDistributionPoints)
           (when critical? (bad! 'crl-distribution-points:critical-but-unsupported))]
          ;; 4.2.1.14 Inhibit anyPolicy
          [(equal? ext-id id-ce-inhibitAnyPolicy)
           (when critical? (bad! 'inhibit-anyPolicy:critical-but-unsupported))]
          ;; 4.2.1.15 Freshest CRL
          [(equal? ext-id id-ce-freshestCRL)
           (when critical? (bad! 'freshest-crl:critical-but-unsupported))]
          ;; Other: ignore unless critical
          [else (when critical? (bad! 'unknown-extension:critical-but-unsupported))]))
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
        (unless (ok-signature? (send issuer get-public-key))
          (add-error 'bad-signature))
        ;; 6.1.3 (a)(2) currently valid; checked in check-valid-period
        (void)
        ;; 6.1.3 (a)(3) (not revoked)
        (void 'CRL-UNSUPPORTED)
        ;; 6.1.3 (a)(4) issuer
        (unless (Name-equal? (get-issuer) (send issuer get-subject))
          (add-error 'issuer:name-mismatch))
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
        ;; 6.1.4 (c-f) handled by get-public-key method instead
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
        ;; 6.1.5 (c-e) handled by get-public-key method instead
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

    ;; ----------------------------------------
    ;; Checking suitability for a purpose

    (define/public (suitable-for-tls-server? host)
      (null? (check-suitable-for-tls-server host)))

    (define/public (check-suitable-for-tls-server host)
      ;; FIXME: add security level check?
      ;; FIXME: add validity period check?
      ;; References:
      ;; - https://tools.ietf.org/html/rfc5246#section-7.4.2
      ;; - https://tools.ietf.org/html/rfc5280#section-4.2.1.12
      ;; tls-key-uses is approximation; actually depends on TLS cipher negotiated
      (define tls-key-uses '(digitalSignature keyEncipherment keyAgreement))
      (append (cond [(for/or ([use (in-list tls-key-uses)]) (ok-key-use? use #t)) '()]
                    [else '(tls:missing-key-usage)])
              (cond [(ok-extended-key-use? id-kp-serverAuth #t) '()]
                    [else '(tls:missing-extended-key-use)])
              (cond [(or (for/or ([pattern (in-list (get-subject-alt-name 'dNSName))])
                           (host-matches? host pattern))
                         (and TLS-USE-COMMON-NAME?
                              (for/or ([cn (in-list (get-subject-common-names))])
                                (and cn (host-matches? host cn)))))
                     '()]
                    [else '(tls:host-mismatch)])))

    (define/public (check-suitable-for-tls-client [name #f])
      (define tls-key-uses '(digitalSignature keyEncipherment keyAgreement))
      (append (cond [(for/or ([use (in-list tls-key-uses)]) (ok-key-use? use #t)) '()]
                    [else '(tls:missing-key-usage)])
              (cond [(ok-extended-key-use? id-kp-clientAuth #t) '()]
                    [else '(tls:missing-extended-key-use)])
              (cond [(or (not name)
                         (GeneralName-equal? name (list 'directoryName (get-subject)))
                         (for/or ([altname (in-list (get-subject-alt-name))])
                           (GeneralName-equal? name altname)))
                     '()]
                    [else '(tls:name-mismatch)])))
    ))

(define (host-matches? host pattern)
  ;; FIXME: support patterns like "*xyz.domain" and "abc*.domain" ??
  (cond [(regexp-match #rx"^[*]([.].*)$" pattern)
         => (match-lambda
              [(list _ suffix) (string-suffix-ci? host suffix)])]
        [else (string-ci=? host pattern)]))

(define (GeneralName-equal? n1 n2)
  ;; FIXME
  (equal? n1 n2))

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

(define (bytes->certificate der #:who [who 'bytes->certificate])
  (new certificate% (der (bytes->immutable-bytes der)) (check-who who)))
