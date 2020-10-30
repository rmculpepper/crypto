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
         "x509-info.rkt"
         "stringprep.rkt"
         (only-in crypto/private/common/asn1 relation-ref))
(provide (all-defined-out))

;; References:
;; - RFC 5280 (https://tools.ietf.org/html/rfc5280)
;; - RFC 6818 (general updates) (https://tools.ietf.org/html/rfc6818)
;; - RFC 8398 and 8399 (Internationalization) (https://tools.ietf.org/html/rfc8398,
;;   https://tools.ietf.org/html/rfc8399)

;; FIXME: asn1 parser returns mutable bytes,strings?

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

;; ============================================================

(define certificate%
  (class* certificate-data% (certificate<%>)
    (init [check? #t])
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

    (when check?
      (define errors (box null))
      (check errors)
      (unless (null? (unbox errors))
        (let ([errors (unbox errors)])
          (raise (exn:x509:certificate (format "invalid X509 certificate\n  errors: ~s" errors)
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

    ;; check : (Boxof (Listof Symbol)) -> Void
    ;; Checks that the certificate is well-formed, without regard for other
    ;; certificates in the chain or any intended purpose. In particular:
    ;; - The signature is not verified!
    ;; - The validity period is not checked.
    ;; - The name, allowed uses, etc are not checked against an intended purpose.
    ;; Errors are pushed onto the contents of errors-box.
    ;; An error symbol should read as a true statement about the certificate
    ;; that points out a fault, rather than reading as a desired property that
    ;; the certificate fails to hold.
    (define/public (check errors-box)
      (define (bad! x)        (set-box! errors-box (cons x (unbox errors-box))))
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
          (bad! 'subject:empty-when-CA/CRL-issuer)))
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
            (bad/ca! 'key-usage:exists)))
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
           (unless (extension-critical? ext)
             (bad/should! 'key-usage:not-critical))
           (define bits (extension-value ext))
           (when (memq 'keyCertSign bits)
             (unless (is-CA?) (bad! 'key-usage:keyCertSign-when-not-CA)))
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
           (when (extension-critical? ext)
             (bad! 'policy-mappings:critical-but-unsupported))]
          ;; 4.2.1.6 Subject Alternative Name
          [(equal? ext-id id-ce-subjectAltName)
           ;; These are interpreted elsewhere, and we don't check wf here.
           (void)]
          ;; 4.2.1.7 Issuer Alternative Name
          [(equal? ext-id id-ce-issuerAltName)
           (unless (not critical?)
             (bad/should! 'issuer-alt-name:critical))]
          ;; 4.2.1.8 Subjct Directory Attributes
          [(equal? ext-id id-ce-subjectDirectoryAttributes)
           (unless (not critical?)
             (bad/ca! 'subject-directory-attributes:critical))]
          ;; 4.2.1.9 Basic Constraints
          [(equal? ext-id id-ce-basicConstraints)
           (when (hash-ref (extension-value ext) 'pathLenConstraint #f)
             (unless (and (is-CA?) (memq 'keyCertSign (get-key-uses)))
               (bad! 'basic-constraints:pathLenConstraint-when-not-CA)))]
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
           (unless (is-CA?) (bad! 'name-constraints:present-when-not-CA))
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
      (void))

    (define/public (ok-validity? [from (current-seconds)] [to from])
      (match-define (list ok-start ok-end) (get-validity-seconds))
      (<= ok-start from to ok-end))

    (define/public (ok-key-usage? uses)
      (define key-uses (get-key-uses))
      (and (for/and ([use (in-list uses)]) (memq use key-uses)) #t))

    ;; ============================================================

    ;; check-link-in-chain : Nat Certificate Validation Boolean -> Void
    (define/public (check-link-in-chain index issuer vi final-in-path?)
      (define (add-error what) (send vi add-error (cons index what)))
      ;; 6.1.3
      (begin
        ;; 6.1.3 (a)(1) verify signature
        (unless (ok-signature? (send issuer get-pk))
          (add-error 'bad-signature))
        ;; 6.1.3 (a)(2) currently valid
        (unless (ok-validity? (send vi get-from-time) (send vi get-to-time))
          (add-error 'bad-validity))
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

    ))

;; ----------------------------------------

(define validation%
  (class object%
    (init N)
    (init-field [max-path-length N]
                [from-time (current-seconds)]
                [to-time from-time]
                [init-policies null]
                ;; state variables
                [name-constraints null]
                [explicit-policy (add1 N)]
                [policy-mapping (add1 N)]
                [inhibit-anypolicy (add1 N)])
    (super-new)

    (define/public (decrement-counters) ;; 6.1.4 (b)
      (cond [(positive? max-path-length)
             (set! max-path-length (sub1 max-path-length))]
            [else (add-error 'max-path-length)])
      (unless (zero? explicit-policy) (set! explicit-policy (sub1 explicit-policy)))
      (unless (zero? policy-mapping) (set! policy-mapping (sub1 policy-mapping)))
      (unless (zero? inhibit-anypolicy) (set! inhibit-anypolicy (sub1 inhibit-anypolicy))))

    (define/public (get-from-time) from-time)
    (define/public (get-to-time) to-time)

    (define errors null)
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

(define certificate-chain%
  (class* object% (certificate-chain<%>)
    ;; chain : (list trust-anchor<%> certificate% ...+)
    ;; Note: In 6.1, trust anchor is not considered part of chain.
    (init-field chain)
    (super-new)

    (define/public (custom-write out mode)
      (fprintf out "#<certificate-chain: ~a>"
               (Name->string (send (get-end-certificate) get-subject))))

    (define N (length (cdr chain))) ;; don't count trust anchor

    (define/public (get-chain) chain)
    (define/public (get-end-certificate) (last chain))
    (define/public (get-trust-anchor) (first chain))

    ;; validate-chain : Store/#f -> (Listof Symbol)
    (define/public (validate-chain store)
      ;; Note: this does not verify that the end certificate is valid for
      ;; any particular *purpose*.
      (define vi (new validation% (N N)))
      (define ta (get-trust-anchor))
      (unless (is-a? ta certificate%)
        (send vi add-error (cons 0 'trust-anchor:not-certificate)))
      (unless (and store (send store trust? ta))
        (send vi add-error (cons 0 'trust-anchor:not-trusted)))
      (for ([issuer (in-list chain)]
            [cert (in-list (cdr chain))]
            [index (in-naturals 1)])
        (send cert check-link-in-chain index issuer vi (= index N)))
      (send vi get-errors))

    ))

;; ============================================================

;; build-chains : certificate% x509-store<%> -> (Listof certificate-chain%)
(define (build-chains end-cert [other-untrusted-certs null] #:store store0)
  (define store (send store0 add #:untrusted-certs other-untrusted-certs))
  (define (loop chains)
    (apply append (map loop1 chains)))
  (define (loop1 chain)
    (define issuer-certs
      (filter (lambda (cert) (not (member cert chain)))
              (remove-duplicates ;; FIXME
               (send store lookup-by-subject (send (car chain) get-issuer)))))
    (define-values (trusted-certs untrusted-certs)
      (partition (lambda (c) (send store trust? c)) issuer-certs))
    (append (map (lambda (c) (new certificate-chain% (chain (cons c chain))))
                 trusted-certs)
            (loop (map (lambda (c) (cons c chain)) untrusted-certs))))
  (loop1 (list end-cert)))

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
           (ormap constraint-matches? relevant)]
          [(eq? mode 'exclude)
           (not (ormap constraint-matches? relevant))]))
  (define (constraint-matches? gn)
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
       (or (string-ci=? name pattern)
           (string-suffix-ci? name (string-append "." pattern)))]
      [(directoryName) ;; name : Name
       (Name-prefix? pattern name)]
      [(uniformResourceIdentifier) ;; name : IA5String
       ;; FIXME
       #f]
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
      [else #f]))
  (andmap layer-name-ok? cs))

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
