#lang racket/base
(require racket/match
         racket/class
         racket/date
         crypto
         net/base64
         asn1
         "x509-asn1.rkt"
         (only-in crypto/private/common/asn1 relation-ref))

;; References:
;; - RFC 5280 (https://tools.ietf.org/html/rfc5280)
;; - RFC 6818 (general updates) (https://tools.ietf.org/html/rfc6818)
;; - RFC 8398 and 8399 (Internationalization) (https://tools.ietf.org/html/rfc8398,
;;   https://tools.ietf.org/html/rfc8399)

;; read-pem-chain : InputPort -> (Listof Bytes)
(define (read-pem-chain in)
  (define (read/expect-start)
    (match (read-line in 'any)
      [(? eof-object?) null]
      [(regexp #rx"^-----BEGIN CERTIFICATE-----$")
       (read/contents)]
      [_ (read/expect-start)]))
  (define (read/contents)
    (define out (open-output-bytes))
    (let loop ()
      (match (read-line in 'any)
        [(? eof-object?) null] ;; FIXME: error, incomplete?
        [(regexp #rx"^-----END CERTIFICATE-----$")
         (cons (base64-decode (get-output-bytes out))
               (read/expect-start))]
        [(? string? s) (begin (write-string s out) (loop))])))
  (read/expect-start))

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

(define certificate%
  (class object%
    (init-field der)
    (super-new)

    (define cert (bytes->asn1 Certificate der))
    (define tbs (hash-ref cert 'tbsCertificate))

    (define/public (get-cert-signature-alg)
      (hash-ref cert 'signatureAlgorithm))
    (define/public (get-cert-signature-bytes)
      (match (hash-ref cert 'signature)
        [(bit-string sig-bytes 0) sig-bytes]))
    (define/public (get-cert-tbs) tbs)

    (define/public (ok-signature? issuer-pk)
      (define vcert (bytes->asn1 Certificate-for-verify-sig der))
      (define tbs-der (hash-ref vcert 'tbsCertificate))
      (define alg (hash-ref vcert 'signatureAlgorithm))
      (define alg-oid (hash-ref alg 'algorithm))
      ;; FIXME: check issuer-pk is appropriate for alg
      (unless (eq? #f (hash-ref alg 'parameters #f))
        (error 'verify-signature "internal error: parameters not supported"))
      (define di (relation-ref SIGNING 'oid (hash-ref alg 'algorithm) 'digest))
      (digest/verify issuer-pk di tbs-der (get-cert-signature-bytes)))

    ;; TBSCertificate component accessors
    (define/public (get-version) (hash-ref tbs 'version))
    (define/public (get-serial-number) (hash-ref tbs 'serialNumber))
    (define/public (get-signature-alg) (hash-ref tbs 'signature))
    (define/public (get-issuer) (hash-ref tbs 'issuer))
    (define/public (get-validity) (hash-ref tbs 'validity))
    (define/public (get-subject) (hash-ref tbs 'subject))
    (define/public (get-spki) (hash-ref tbs 'subjectPublicKeyInfo))
    (define/public (get-issuer-unique-id) (hash-ref tbs 'issuerUniqueID #f))
    (define/public (get-subject-unique-id) (hash-ref tbs 'subjectUniqueID #f))
    (define/public (get-extensions) (hash-ref tbs 'extensions null))

    (define/public (get-pk) (datum->pk-key (get-spki) 'SubjectPublicKeyInfo))

    (define/public (is-CA?)
      (cond [(get-extension id-ce-basicConstraints)
             => (lambda (ext) (hash-ref (extension-value ext) 'cA))]
            [else #f]))
    (define/public (is-CRL-issuer?) (and (memq 'cRLSign (get-key-uses)))) ;; FIXME: and (is-CA?)
    (define/public (is-self-signed?) #f) ;; FIXME
    (define/public (get-key-uses)
      (cond [(get-extension id-ce-keyUsage) => extension-value] [else null]))

    (define/public (get-extension id)
      (for/or ([ext (in-list (get-extensions))] #:when (equal? id (extension-id ext))) ext))

    (define errors null) ;; mutated
    (define/public (get-errors) errors)

    (define/private (check reason ok) (unless ok (set! errors (cons reason errors))))
    (define/private (check-should reason ok) (unless ok (set! errors (cons reason errors))))
    (define/private (check-ca reason ok) (unless ok (set! errors (cons reason errors))))

    ;; Checks that the certificate is well-formed, without regard for other
    ;; certificates in the chain. (For example, the signature is not verified.)
    (begin
      ;; 4.1.1.2
      (check 'signature-algs-same (equal? (get-cert-signature-alg) (get-signature-alg)))
      ;; 4.1.1.3
      ;; -- 'signature-valid, checked later
      ;; 4.1.2.1    -- note: v3 = 2, etc
      (cond [(pair? (get-extensions))
             (check 'version-when-extensions (= (get-version) v3))]
            [(or (get-issuer-unique-id) (get-subject-unique-id))
             (check-should 'version-when-unique-id (= (get-version) v2))
             (check 'version-when-unique-id (member (get-version) (list v2 v3)))]
            [else
             (check-should 'version-when-basic (= (get-version) v1))
             (check 'version-when-basic (member (get-version) (list v1 v2 v3)))])
      ;; 4.1.2.2
      (check-ca 'serial-number-positive (positive? (get-serial-number)))
      ;; -- 'serial-number-unique, cannot check
      ;; 4.1.2.3
      ;; -- 'signature-algs-same, checked in 4.1.1.2
      ;; 4.1.2.4 Issuer
      (check 'issuer-non-empty (DN-not-empty? (get-issuer)))
      (check 'issuer-wf (wf-DN? (get-issuer)))
      ;; 4.1.2.5 Validity
      ;; -- 'validity-encoding-by-year (CA-MUST), not checked because client MUST accept both
      ;; -- 'validity-time, checked later
      ;; 4.1.2.5.{1,2}
      (match (get-validity)
        [(hash-table ['notBefore ok-start] ['notAfter ok-end])
         (check 'validity-wf-start (wf-time? ok-start))
         (check 'validity-wf-end (wf-time? ok-end))])
      ;; 4.1.2.6 Subject
      (when (or (is-CA?) (is-CRL-issuer?))
        (check 'subject-non-empty (DN-not-empty? (get-subject))))
      (check 'subject-wf (wf-DN? (get-subject)))
      (unless (DN-not-empty? (get-subject))
        (check 'subject-empty=>subjectAltName
               (cond [(get-extension id-ce-subjectAltName) => extension-critical?]
                     [else #f])))
      ;; ----------------------------------------
      ;; 4.2 Certificate Extensions
      (check 'extensions-unique (unique-by-key? (get-extensions) extension-id))
      ;; constraints on extension that must be present
      (begin
        ;; 4.2.1.1 Authority Key Identifier
        (unless (and (is-CA?) (is-self-signed?))
          (check 'authority-key-id-exists (get-extension id-ce-authorityKeyIdentifier)))
        ;; 4.2.1.2 Subject Key Identifier
        (check-should 'subject-key-id-exists (get-extension id-ce-subjectKeyIdentifier))
        ;; 4.2.1.3 Key Usage
        (when (is-CA?)
          (check-ca 'key-usage-exists (get-extension id-ce-keyUsage)))
        (void))
      ;; constraints on extensions when present
      (for ([ext (in-list (get-extensions))])
        (define ext-id (extension-id ext))
        (define critical? (extension-critical? ext))
        (cond
          ;; 4.2.1.1 Authority Key Identifier
          [(equal? ext-id id-ce-authorityKeyIdentifier)
           (check-ca 'authority-key-id-non-critical (not critical?))]
          ;; 4.2.1.2 Subject Key Identifier
          [(equal? ext-id id-ce-subjectKeyIdentifier)
           (check-ca 'subject-key-id-non-critical (not critical?))]
          ;; 4.2.1.3 Key Usage
          [(equal? ext-id id-ce-keyUsage)
           (check-ca 'key-usage-critical (extension-critical? ext))
           (define bits (extension-value ext))
           (when (memq 'keyCertSign bits)
             (check 'key-usage-keyCertSign=>CA (is-CA?)))
           (check 'key-usage-non-empty (pair? bits))]
          ;; 4.2.1.4 Certificate Policies
          [(equal? ext-id id-ce-certificatePolicies)
           (define policies (extension-value ext))
           (check 'policies-unique (unique-by-key? policies policy-id))
           ;; FIXME: check policies?
           (when (extension-critical? ext)
             (check 'policies-critical-but-not-supported #f))]
          ;; 4.2.1.5 Policy Mappings
          [(equal? ext-id id-ce-policyMappings)
           (when (extension-critical? ext)
             (check 'policy-mappings-not-supported #f))]
          ;; 4.2.1.6 Subject Alternative Name
          [(equal? ext-id id-ce-subjectAltName)
           ;; FIXME: wf variants (eg, wf email address, etc)
           (void)]
          ;; 4.2.1.7 Issuer Alternative Name
          [(equal? ext-id id-ce-issuerAltName)
           (check 'issuer-alt-name-non-critical (not critical?))]
          ;; 4.2.1.8 Subjct Directory Attributes
          [(equal? ext-id id-ce-subjectDirectoryAttributes)
           (check 'subject-directory-attributes-non-critical (not critical?))]
          ;; 4.2.1.9 Basic Constraints
          [(equal? ext-id id-ce-basicConstraints)
           (when (hash-ref (extension-value ext) 'pathLenConstraint #f)
             (check 'basic-constraints-path-len-constraint
                    (and (is-CA?) (memq 'keyCertSign (get-key-uses)))))]
          ;; 4.2.1.10 Name Constraints
          [(equal? ext-id id-ce-nameConstraints)
           ;; FIXME!
           (check 'name-constraints=>CA (is-CA?))
           (check 'name-constraints-not-supported (not critical?))]
          ;; 4.2.1.11 Policy Constraints
          [(equal? ext-id id-ce-policyConstraints)
           ;; FIXME!
           (check 'policy-constraints-not-supported (not critical?))]
          ;; 4.2.1.12 Extended Key Usage
          [(equal? ext-id id-ce-extKeyUsage)
           ;; FIXME!
           (check 'extended-key-usage-not-supported (not critical?))]
          ;; 4.2.1.13 CRL Distribution points
          [(equal? ext-id id-ce-cRLDistributionPoints)
           (check 'crl-distribution-points-not-supported (not critical?))]
          ;; 4.2.1.14 Inhibit anyPolicy
          [(equal? ext-id id-ce-inhibitAnyPolicy)
           (check 'inhibit-anyPolicy-not-supported (not critical?))]
          ;; 4.2.1.15 Freshest CRL
          [(equal? ext-id id-ce-freshestCRL)
           (check 'freshest-crl-not-supported (not critical?))]
          ;; Other: ignore unless critical
          [else
           (check 'unknown-critical-extension-not-supported (not critical?))]))
      (void))

    (define/public (get-validity-seconds)
      (match (get-validity)
        [(hash-table ['notBefore ok-start] ['notAfter ok-end])
         (list (asn1-time->seconds ok-start) (asn1-time->seconds ok-end))]))

    (define/public (ok-validity? [from (current-seconds)] [to from])
      (match-define (list ok-start ok-end) (get-validity-seconds))
      (<= ok-start from to ok-end))

    (define/public (ok-key-usage? uses)
      (define key-uses (get-key-uses))
      (and (for/and ([use (in-list uses)]) (memq use key-uses)) #t))

    ))

(define (asn1-time->seconds t)
  (define (map-num ss) (map string->number ss))
  (match t
    [(list 'utcTime
           (regexp #px"^([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z$"
                   (cons _ (app map-num (list YY MM DD hh mm ss)))))
     (define YYYY (+ YY (if (< YY 50) 2000 1900)))
     (find-seconds ss mm hh DD MM YYYY #f)]
    [(list 'generalTime
           (regexp #px"^([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z$"
                   (cons _ (app map-num (list YYYY MM DD hh mm ss)))))
     (find-seconds ss mm hh DD MM YYYY #f)]))

(define (unique-by-key? xs get-key)
  (let ([h (make-hash)])
    (for ([x (in-list xs)]) (hash-update! h (get-key x) add1 0))
    (for/and ([v (in-hash-values h)]) (<= v 1))))

(define (DN-not-empty? dn)
  (match dn
    [(list 'rdnSequence (? pair?)) #t]
    [_ #f]))

(define (wf-DN? dn)
  ;; FIXME: see 4.1.2.4, 4.1.2.6
  ;; -- 'modern-strings (CA-MUST), not checked, FIXME
  #t)

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

(define (get-cert-chain file)
  (map (lambda (der) (new certificate% (der der)))
       (call-with-input-file file read-pem-chain)))

;; ----------------------------------------

(require racket/pretty)
(pretty-print-columns 160)
(require crypto crypto/all)
(use-all-factories!)
