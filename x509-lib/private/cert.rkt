#lang racket/base
(require racket/match
         racket/class
         racket/list
         racket/string
         racket/date
         racket/serialize
         asn1
         asn1/util/time
         "interfaces.rkt"
         "asn1.rkt"
         "stringprep.rkt")
(provide (all-defined-out))

;; References:
;; - RFC 5280 (https://tools.ietf.org/html/rfc5280)
;; - RFC 6818 (general updates) (https://tools.ietf.org/html/rfc6818)
;; - RFC 8398 and 8399 (Internationalization) (https://tools.ietf.org/html/rfc8398,
;;   https://tools.ietf.org/html/rfc8399)

;; ============================================================

(define certificate-data%
  (class* object% (certificate-data<%>)
    (init-field der)
    (super-new)

    (define/public (get-der) der)

    (define cert (bytes->asn1 Certificate der))
    (define tbs (hash-ref cert 'tbsCertificate))

    (define/public (has-same-public-key? other-cert)
      (equal? (get-spki) (send other-cert get-spki)))

    (define/public (get-cert-signature-info)
      (define vcert (bytes->asn1 Certificate-for-verify-sig der))
      (values (hash-ref vcert 'signatureAlgorithm)
              (hash-ref vcert 'tbsCertificate)
              (match (hash-ref vcert 'signature)
                [(bit-string sig-bytes 0) sig-bytes])))

    ;; TBSCertificate component accessors
    (define/public (get-version) (hash-ref tbs 'version))
    (define/public (get-serial-number) (hash-ref tbs 'serialNumber))
    (define/public (get-issuer) (hash-ref tbs 'issuer))
    (define/public (get-validity) (hash-ref tbs 'validity))
    (define/public (get-subject) (hash-ref tbs 'subject))
    (define/public (get-spki) (hash-ref tbs 'subjectPublicKeyInfo))
    (define/public (get-issuer-unique-id) (hash-ref tbs 'issuerUniqueID #f))
    (define/public (get-subject-unique-id) (hash-ref tbs 'subjectUniqueID #f))
    (define/public (get-extensions) (hash-ref tbs 'extensions null))

    (define/public (get-subject-common-names)
      (match (get-subject)
        [(list 'rdnSequence rdns)
         (for*/list ([rdn (in-list rdns)] [av (in-list rdn)]
                     #:when (equal? (hash-ref av 'type) id-at-commonName))
           (get-attr-value (hash-ref av 'value) values))]))

    (define/public (is-CA?)
      (let ([bc (get-extension-value id-ce-basicConstraints #f)])
        (and bc (hash-ref bc 'cA))))
    (define/public (is-self-issued?) ;; 6.1
      (let ([subject (get-subject)] [issuer (get-issuer)])
        (Name-equal? subject issuer)))
    (define/public (is-self-signed?)
      ;; FIXME
      #f)

    (define/public (get-extension id)
      (for/or ([ext (in-list (get-extensions))] #:when (equal? id (extension-id ext))) ext))
    (define/public (get-extension-value id default)
      (cond [(get-extension id) => extension-value] [else default]))

    (define/public (get-key-uses)
      (get-extension-value id-ce-keyUsage null))
    (define/public (ok-key-use? use [default #f])
      (cond [(get-extension-value id-ce-keyUsage #f)
             => (lambda (uses) (and (memq use uses) #t))]
            [else (if (procedure? default) (default) default)]))

    (define/public (get-ekus [default null])
      (get-extension-value id-ce-extKeyUsage default))

    (define/public (get-eku eku) ;; (U 'yes 'no 'unset)
      (cond [(get-ekus #f)
             => (lambda (ekus) (if (member eku ekus) 'yes 'no))]
            [else 'unset]))

    (define/public (get-name-constraints)
      (get-extension-value id-ce-nameConstraints #f))
    (define/public (get-subject-alt-names [kind #f])
      (define altnames (get-extension-value id-ce-subjectAltName null))
      (cond [kind (for/list ([altname (in-list altnames)] #:when (eq? kind (car altname)))
                    (cadr altname))]
            [else altnames]))

    (define/public (get-crl-distribution-points)
      (get-extension-value id-ce-cRLDistributionPoints null))

    (define/public (get-ocsp-uris)
      (filter values
              (for/list ([loc (in-list (get-ocsp-locations))])
                (match loc [(list 'uniformResourceIdentifier uri) uri] [_ #f]))))

    (define/public (get-ocsp-locations)
      (define aia (get-extension-value id-pe-authorityInfoAccess null))
      (for/list ([ad (in-list aia)]
                 #:when (equal? (hash-ref ad 'accessMethod) id-ad-ocsp))
        (hash-ref ad 'accessLocation)))

    (define/public (get-validity-seconds)
      (match (get-validity)
        [(hash-table ['notBefore ok-start] ['notAfter ok-end])
         (list (asn1-time->seconds ok-start) (asn1-time->seconds ok-end))]))

    ;; ============================================================
    ;; Checking well-formed

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
      (unless (equal? (hash-ref cert 'signatureAlgorithm)
                      (hash-ref tbs 'signature))
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
      (when (or (is-CA?) (memq 'cRLSign (get-key-uses)))
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
           (when (member anyExtendedKeyUsage (get-ekus))
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
          ;; RFC 6960 (PKIX OCSP)
          [(equal? ext-id id-pkix-ocsp-nocheck)
           (void)]
          ;; Other: ignore unless critical
          [else (when critical? (bad! 'unknown-extension:critical-but-unsupported))]))
      errors)
    ))

;; ============================================================

(define (asn1-time->seconds t)
  (define (map-num ss) (map string->number ss))
  (match t
    [(list 'utcTime s)
     ;; See 4.1.2.5.1 for interpretation (YY in range [1950-2049]).
     (asn1-utc-time->seconds s)]
    [(list 'generalTime s)
     (asn1-generalized-time->seconds s)]))

(define (unique-by-key? xs get-key)
  (let ([h (make-hash)])
    (for ([x (in-list xs)]) (hash-update! h (get-key x) add1 0))
    (for/and ([v (in-hash-values h)]) (<= v 1))))

;; String for display and debugging, don't rely on contents.
;; (Among other issues, chars like #\, and #\= in value are not escaped.)
(define (Name->string n)
  (match n
    [(list 'rdnSequence rdns)
     (string-join
      (flatten
       (for*/list ([rdn (in-list rdns)]
                   [av (in-list rdn)])
         (define value (get-attr-value (hash-ref av 'value) (lambda (x) #f)))
         (match (and value (hash-ref av 'type))
           [(== id-at-countryName) (format "C=~a" value)]
           [(== id-at-stateOrProvinceName) (format "ST=~a" value)]
           [(== id-at-localityName) (format "L=~a" value)]
           [(== id-at-commonName) (format "CN=~a" value)]
           [(== id-at-organizationName) (format "O=~a" value)]
           [(== id-at-organizationalUnitName) (format "OU=~a" value)]
           [_ null])))
      ",")]))

(define (Name-equal? dn1 dn2)
  (Name-match? dn1 dn2 =))
(define (Name-prefix? dn1 dn2) ;; is dn1 a prefix of dn2?
  (Name-match? dn1 dn2 <=))

(define (Name-match? dn1 dn2 cmp)
  ;; Does anyone actually implement the section 7 name matching rules?
  ;; See https://github.com/golang/go/issues/31440 for survey.
  (define (unwrap v)
    (match (get-attr-value v (lambda (v) v))
      [(? string? s) (ldap-stringprep s #:on-error (lambda (x) x))]
      [other other]))
  (define (same? v1 v2)
    (if (and (string? v1) (string? v2)) (string-ci=? v1 v2) (equal? v1 v2)))
  (match* [dn1 dn2]
    [[(list 'rdnSequence rdns1) (list 'rdnSequence rdns2)]
     (and (cmp (length rdns1) (length rdns2))
          (for/and ([rdn1 (in-list rdns1)] [rdn2 (in-list rdns2)])
            (define (rdn->h rdn)
              (for/fold ([h (hash)]) ([av (in-list rdn)])
                (hash-set h (hash-ref av 'type) (hash-ref av 'value))))
            (define h1 (rdn->h rdn1))
            (define h2 (rdn->h rdn2))
            ;; Note: if a (bad) DN had the same attr type multiple times in the
            ;; SET, the hash loses information. So iterate over SETs instead.
            (and (for/and ([av1 (in-list rdn1)])
                   (match-define (hash-table ['type k] ['value v1]) av1)
                   (same? (unwrap v1) (unwrap (hash-ref h2 k #f))))
                 (for/and ([av2 (in-list rdn2)])
                   (match-define (hash-table ['type k] ['value v2]) av2)
                   (same? (unwrap v2) (unwrap (hash-ref h1 k #f)))))))]))

(define (Name-empty? dn)
  (match dn [(list 'rdnSequence rdns) (null? rdns)]))

(define (get-attr-value ds handle-other)
  (match ds
    [(list 'printableString (? string? s)) s]
    [(list 'universalString (? string? s)) s]
    [(list 'utf8String (? string? s)) s]
    [(list 'bmpString (? string? s)) s]
    [(? string? s) s]
    [_ (handle-other ds)]))

(define (wf-time? v)
  (match v
    ;; These regexps can be simple because of existing asn1 parser checks.
    [(list 'utcTime (regexp #px"^[0-9]{12}Z$")) #t]
    [(list 'generalTime (regexp #px"^[0-9]{14}Z$")) #t]
    [_ #f]))

(define (extension-id ext) (hash-ref ext 'extnID))
(define (extension-critical? ext) (hash-ref ext 'critical))
(define (extension-value ext) (hash-ref ext 'extnValue))

(define (policy-id p) (hash-ref p 'policyIdentifier))

;; ============================================================

;; openssl-Name-hash : Name -> Nat
;; Name hash compatible with OpenSSL X509_NAME_hash().
(define (openssl-Name-hash name)
  (define cname (openssl-Name-canon name))
  (define cname-sha1 (sha1-bytes cname))
  (integer-bytes->integer cname-sha1 #f #f 0 4))

(define openssl-Name-canon-memo-table (make-weak-hasheq))

;; ossl-Name-canon : Name -> Bytes
;; Name canonicalization compatible with OpenSSL.
(define (openssl-Name-canon name)
  (hash-ref! openssl-Name-canon-memo-table name
             (lambda () (openssl-Name-canon* name))))
(define (openssl-Name-canon* name)
  (define (rdn-canon rdn)
    (map av-canon rdn))
  (define (av-canon av)
    (hash 'type (hash-ref av 'type)
          ;; All attribute values inside of RelativeDistinguishedName
          ;; are either string types or choices or string types.
          'value (match (hash-ref av 'value)
                   [(? string? s) (openssl-string-canon s)]
                   [(list 'teletexString bs)
                    ;; FIXME: ???
                    (openssl-string-canon (bytes->string/latin-1 bs))]
                   [(list _ (? string? s)) (openssl-string-canon s)])))
  (match name
    [(list 'rdnSequence rdns)
     (apply bytes-append
            (map (lambda (cdn) (asn1->bytes/DER CanonRelativeDistinguishedName cdn))
                 (map rdn-canon rdns)))]))

(define (openssl-string-canon s)
  ;; Ignore leading and trailing spaces; space is #x09-0D, #x20
  ;; Collapse multiple spaces to #\space
  ;; If ASCII, then lowercase; otherwise, just copy
  ;; IIUC, no unicode canonicalization done
  (define (isspace? b) (or (<= #x09 b #x0D) (= b #x20)))
  (define (isupper? b) (<= (char->integer #\A) b (char->integer #\Z)))
  (define (tolower b) (+ b (- (char->integer #\a) (char->integer #\A))))
  (define bs (string->bytes/utf-8 s))
  (define out (open-output-bytes))
  (define start (let loop ([i 0])
                  (cond [(= i (bytes-length bs)) i]
                        [(isspace? (bytes-ref bs i)) (loop (add1 i))]
                        [else i])))
  (define end (add1 (let loop ([i (sub1 (bytes-length bs))])
                      (cond [(<= i start) i]
                            [(isspace? (bytes-ref bs i)) (loop (sub1 i))]
                            [else i]))))
  (for/fold ([skip-sp? #f]) ([b (in-bytes bs)])
    (cond [(isspace? b) (begin (unless skip-sp? (write-char #\space out)) #t)]
          [(isupper? b) (begin (write-byte (tolower b) out) #f)]
          [else (begin (write-byte b out) #f)]))
  (get-output-string out))

(define CanonAttributeTypeAndValue
  (SEQUENCE (type OBJECT-IDENTIFIER) (value UTF8String)))
(define CanonRelativeDistinguishedName (SET-OF CanonAttributeTypeAndValue))

;; ============================================================

(define (host-matches? host pattern)
  ;; Patterns like "*xyz.domain" and "abc*.domain" are not supported.
  (cond [(regexp-match #rx"^[*]([.].*)$" pattern)
         => (match-lambda
              [(list _ suffix)
               (define prefix-len (- (string-length host) (string-length suffix)))
               (and (string-suffix-ci? host suffix)
                    ;; RFC 6125 Section 7.2 recommends agains wildcards; Appendix
                    ;; B mentions RFC 2818 interpretation: RFC 2818 Section 3.1
                    ;; says wildcard matches *one* domain name component. So
                    ;; forbid "." in prefix. Also check prefix is not empty.
                    (regexp-match? #rx"^[^.]+$" host 0 prefix-len))])]
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

(define serializable-certificate<%>
  (interface*
   ()
   ([prop:serializable
     (make-serialize-info (lambda (c) (send c -serialize))
                          #'deserialize-info:certificate%
                          #f
                          (or (current-load-relative-directory)
                              (current-directory)))])))

(define deserialize-info:certificate%
  (make-deserialize-info
   (lambda (der reject-ekus replace-ekus)
     (cond [(or (pair? reject-ekus) replace-ekus)
            (new certificate% (der (bytes->immutable-bytes der))
                 (reject-ekus reject-ekus) (replace-ekus replace-ekus)
                 (check-who 'deserialize-certificate))]
           [else (bytes->certificate der #:who 'deserialize-certificate)]))
   (lambda () (error 'deserialize-cert "cycles not allowed"))))

;; ============================================================

(define certificate%
  (class* certificate-data% (-certificate<%> serializable-certificate<%>)
    (init [check-who 'certificate])
    (inherit-field der)
    (init-field [reject-ekus null] ;; (Listof OID)
                [replace-ekus #f]) ;; #f or (Listof OID) -- #f means use cert EKUs
    (inherit get-der
             get-spki
             get-subject
             check)
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

    (define/public (equal-to? other [recur equal?])
      (and (recur (get-der) (send other get-der))
           (recur reject-ekus (get-field reject-ekus other))
           (recur replace-ekus (get-field replace-ekus other))))

    (define/public (equal-hash-code-of recur)
      (recur (get-der)))
    (define/public (equal-secondary-hash-code-of recur)
      (recur (get-der)))

    (define/public (custom-write out)
      (fprintf out "#<certificate: ~a>" (Name->string (get-subject))))
    (define/public (custom-display out)
      (custom-write out))

    (define/public (-serialize)
      (vector der reject-ekus replace-ekus))

    ;; ----------------------------------------

    (define/override (get-eku eku)
      (define (member* x xs) (or (member x xs) (member anyExtendedKeyUsage xs)))
      (cond [(member* eku reject-ekus) 'no]
            [replace-ekus (if (member* eku replace-ekus) 'yes 'no)]
            [else (super get-eku eku)]))
    ))

;; ============================================================

;; cert-cache : WeakHash[Bytes => Certificate]
(define cert-cache (make-weak-hash))

(define (bytes->certificate der #:who [who 'bytes->-certificate])
  (let ([der (bytes->immutable-bytes der)])
    (hash-ref! cert-cache der (lambda () (make-certificate der who)))))

(define (make-certificate der who)
  (new certificate% (der der) (check-who who)))

;; ============================================================

;; Support for OpenSSL's TRUSTED CERTIFICATE: a certificate with additional
;; trusted and rejected EKUs.
(module+ openssl-trusted-cert
  (provide (all-defined-out))

  (define CertAux
    (SEQUENCE
     [trust (SEQUENCE-OF OBJECT-IDENTIFIER) #:optional]
     [reject #:implicit 0 (SEQUENCE-OF OBJECT-IDENTIFIER) #:optional]
     [alias UTF8String #:optional]
     [keyid OCTET-STRING #:optional]))

  (define (bytes->certificate/override-uses der #:who [who 'bytes->certificate/override-uses])
    (define in (open-input-bytes der))
    (define cert-der (begin (read-asn1 ANY in) (subbytes der 0 (file-position in))))
    (define aux (read-asn1 CertAux in))
    (new certificate% (der (bytes->immutable-bytes cert-der))
         (reject-ekus (hash-ref aux 'reject null))
         (replace-ekus (hash-ref aux 'trust #f)))))
