#lang racket/base
(require racket/match
         racket/class
         racket/date
         crypto
         asn1
         crypto/pem
         "x509-asn1.rkt"
         "stringprep.rkt"
         (only-in crypto/private/common/asn1 relation-ref))

;; References:
;; - RFC 5280 (https://tools.ietf.org/html/rfc5280)
;; - RFC 6818 (general updates) (https://tools.ietf.org/html/rfc6818)
;; - RFC 8398 and 8399 (Internationalization) (https://tools.ietf.org/html/rfc8398,
;;   https://tools.ietf.org/html/rfc8399)

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
    (init-field der [issuer-obj #f])
    (super-new)

    (define/public (get-der) der)
    (define/public (get-next) issuer-obj)

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
    (define/public (is-self-issued?) ;; 6.1
      (let ([subject (get-subject)] [issuer (get-issuer)])
        (DN-match? subject issuer)))
    (define/public (is-self-signed?)
      ;; FIXME
      #f)
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

    ;; ============================================================

    (define/public (validate-chain)
      ;; Note: this does not verify that this certificate is valid for
      ;; any particular *purpose*.
      (define vi (new validation% (store root)))
      (check-chain vi 1)
      (send vi get-errors))

    ;; FIXME: change to include trust anchor (as certificate%) at end of chain?

    (define/public (check-chain vi [depth 1])
      (define (final-in-path?) (= depth 1))
      (define (add-error what) (send vi add-error (cons depth what)))
      ;; 6.1.3
      (begin
        (cond [issuer-obj
               (send issuer-obj check-chain vi (add1 depth))
               ;; 6.1.3 (a)(1) verify signature
               (unless (ok-signature? (send issuer-obj get-pk))
                 (add-error 'ok-signature))
               ;; 6.1.3 (a)(4) issuer
               (unless (DN-match? (get-issuer) (send issuer-obj get-subject))
                 (add-error 'issuer-matches))]
              [else ;; use trust anchor
               (send vi initialize depth)
               (define ta (send vi get-trust-anchor (get-issuer)))
               (unless ta
                 (add-error 'trust-anchor))
               (when ta
                 ;; 6.1.3 (a)(1) verify signature
                 (unless (ok-signature? (send ta get-pk))
                   (add-error 'ok-signature/trust-anchor))
                 ;; 6.1.3 (a)(4) issuer
                 (unless (DN-match? (get-issuer) (send ta get-subject))
                   (add-error 'issuer-matches/trust-anchor)))
               (void)])
        ;; 6.1.3 (a)(2)
        (unless (ok-validity? (send vi get-from-time) (send vi get-to-time))
          (add-error 'ok-validity))
        ;; 6.1.3 (a)(3) (not revoked)
        (void) ;; FIXME?
        ;; 6.1.3 (b)
        (unless (and (is-self-issued?) (final-in-path?))
          ;; FIXME: check (get-subject) is in permitted-subtrees
          ;; FIXME: check each subjectAltName is in permitted-subtrees
          (void))
        ;; 6.1.3 (c)
        (unless (and (is-self-issued?) (final-in-path?))
          ;; FIXME: check (get-subject) is not in excluded-subtrees
          ;; FIXME: check each subjectAltName is not in excluded-subtrees
          (void))
        ;; 6.1.3 (d)
        (begin
          ;; FIXME: if valid-policy-tree is not #f and this cert has certificate
          ;; policies, process the policies.
          (void))
        ;; 6.1.3 (e) if no certificate policies, set valid-policy-tree to #f
        (void) ;; FIXME
        ;; 6.1.3 (f) explicit-policy > 0 or valid-policy-tree is not #f
        (void))
      ;; 6.1.4
      (unless (final-in-path?)
        ;; 6.1.4 (a-b) policy-mappings, policies, ...
        (void) ;; FIXME
        ;; 6.1.4 (c-f) handled by get-pk method instead
        (void 'OK)
        ;; 6.1.4 (g) name constraints, {permitted,excluded}-subtrees
        (void) ;; FIXME
        ;; 6.1.4 (h, l) decrement counters
        (unless (is-self-issued?)
          (send vi decrement-counters))
        ;; 6.1.4 (i, j) policy-mapping, inhibit-anypolicy, ...
        (void) ;; FIXME
        ;; 6.1.4 (k) check CA (reject if no basicConstraints extension)
        (unless (is-CA?) (add-error 'is-CA))
        ;; 6.1.4 (m)
        (let* ([ext (get-extension id-ce-basicConstraints)]
               [plen (and ext (hash-ref (extension-value ext) 'pathLenConstraint #f))])
          (when plen (send vi set-max-path-length plen)))
        ;; 6.1.4 (n)
        (let ([key-uses (get-key-uses)])
          (when (pair? key-uses)
            (unless (memq 'keyCertSign key-uses)
              (add-error 'CA-has-keyCertSign))))
        ;; 6.1.4 (o) already done in certificate% construction
        (void 'OK))
      ;; 6.1.5
      (when (final-in-path?)
        ;; 6.1.5 (a) explicit-policy
        (void) ;; FIXME
        ;; 6.1.5 (b) policies, explicit-policy, ...
        (void) ;; FIXME
        ;; 6.1.5 (c-e) handled by get-pk method instead
        (void 'OK)
        ;; 6.1.5 (f) already done in certificate% construction
        (void 'OK)
        ;; 6.1.5 (g) policies ...
        (void) ;; FIXME
        (void))
      (void))

    ))


;; ============================================================

(define validation%
  (class object%
    (init-field store
                [from-time (current-seconds)]
                [to-time from-time]
                [init-policies null]
                ;; state variables
                [max-path-length #f]
                [explicit-policy #f]
                [policy-mapping #f]
                [inhibit-anypolicy #f])
    (super-new)

    (define/public (initialize n)
      (unless max-path-length (set! max-path-length n))
      (unless explicit-policy (set! explicit-policy (add1 n)))
      (unless policy-mapping (set! policy-mapping (add1 n)))
      (unless inhibit-anypolicy (set! inhibit-anypolicy (add1 n))))

    (define/public (decrement-counters) ;; 6.1.4 (b)
      (cond [(not max-path-length)
             (error 'check/decrement-max-path-length "not initialized")]
            [(positive? max-path-length)
             (set! max-path-length (sub1 max-path-length))]
            [else (add-error 'max-path-length)])
      (unless (zero? explicit-policy) (set! explicit-policy (sub1 explicit-policy)))
      (unless (zero? policy-mapping) (set! policy-mapping (sub1 policy-mapping)))
      (unless (zero? inhibit-anypolicy) (set! inhibit-anypolicy (sub1 inhibit-anypolicy))))

    (define/public (get-trust-anchor dn)
      (define certs (send store lookup-by-subject dn))
      (match (filter (lambda (c) (send store trust? c)) certs)
        [(cons cert _) cert]
        [_ #f]))

    (define/public (get-from-time) from-time)
    (define/public (get-to-time) to-time)

    (define errors null)
    (define/public (get-errors) errors)
    (define/public (add-error what) (set! errors (cons what errors)))

    (define valid-policy-tree #f) ;; ???
    (define permitted-subtrees #f) ;; ???
    (define excluded-subtrees #f) ;; ???

    (define/public (set-max-path-length n)
      (unless max-path-length (error 'set-max-path-length "not initialized"))
      (when (< n max-path-length) (set! max-path-length n)))
    ))

(define trust-anchor<%>
  (interface ()
    get-pk
    get-subject
    ))

;; ============================================================

(define x509-store<%>
  (interface ()
    trust?            ;; certificate% -> Boolean
    lookup-by-subject ;; DN -> (Listof certificate%)
    lookup-by-key-id  ;; Bytes -> (Listof certificate%)
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
  (define-ssl d2i_X509_NAME ;; FIXME: wrap allocator
    (_fun (_pointer = #f) (_ptr i _pointer) _long -> _X509_NAME/null)
    #:wrap (allocator X509_NAME_free))
  (define-ssl X509_NAME_hash (_fun _X509_NAME -> _long))
  (define (NAME-hash dn-der)
    (define dn (d2i_X509_NAME dn-der (bytes-length dn-der)))
    (begin0 (X509_NAME_hash dn) (X509_NAME_free dn))))

(define x509-root-store%
  (class* object% (x509-store<%>)
    (init-field dir)
    (super-new)

    (define/public (trust? cert)
      (for/or ([trusted (in-list (lookup-by-subject (send cert get-subject)))])
        (equal? (send cert get-der) (send trusted get-der))))

    (define/public (lookup-by-subject dn)
      (lookup-by-subject/hash dn))

    (define/public (lookup-by-subject/cn dn)
      ;; PROBLEM: the directory does not always base the filename on the CN,
      ;; because some root certs have dumb CNs. (Ex: chain for google.com
      ;; ending in GlobalSign)
      (define cn (DN-get-common-name dn))
      (define file (build-path dir (format "~a.pem" (regexp-replace* #rx" " cn "_"))))
      ;; (eprintf "looking for ~s\n" file)
      (cond [(file-exists? file)
             (define cert (read-cert-from-file file))
             (if (DN-match? dn (send cert get-subject)) (list cert) null)]
            [else null]))

    (define/public (lookup-by-subject/hash dn)
      (define (padto n s) (string-append (make-string (- n (string-length s)) #\0) s))
      (define base (padto 8 (number->string (dn-hash (asn1->bytes Name dn)) 16)))
      (let loop ([i 0])
        (define file (build-path dir (format "~a.~a" base i)))
        (cond [(file-exists? file)
               (define cert (read-cert-from-file file))
               (if (DN-match? dn (send cert get-subject))
                   (cons cert (loop (add1 i)))
                   (loop (add1 i)))]
              [else null])))

    (define/private (dn-hash dn-der)
      (local-require (submod "." openssl-x509))
      (NAME-hash dn-der))

    (define/private (read-cert-from-file file)
      (match (call-with-input-file* file read-pem-certs)
        [(list der) (new certificate% (der der))]
        [_ (error 'lookup-by-subject "bad certificate PEM file: ~e" file)]))

    (define/public (lookup-by-key-id keyid) null)

    (define/public (add-certificates certs #:trusted? [trusted? #f])
      (send (new x509-store% (parent this))
            add-certificates certs #:trusted? trusted?))
    ))

(define root (new x509-root-store% (dir "/etc/ssl/certs")))

(define x509-empty-store%
  (class* object% (x509-store<%>)
    (super-new)
    (define/public (trust? cert) #f)
    (define/public (lookup-by-subject dn) null)
    (define/public (lookup-by-key-id keyid) null)
    (define/public (add-certificates certs #:trusted? [trusted? #f])
      (send (new x509-store% (parent this))
            add-certificates certs #:trusted? trusted?))
    ))

(define x509-store%
  (class* object% (x509-store<%>)
    (init-field parent
                [trusted-h   '#hash()]
                [dn=>cert    '#hash()]
                [keyid=>cert '#hash()])
    (super-new)

    (define/public (trust? cert)
      (or (hash-ref trusted-h (send cert get-der) #f)
          (send parent trust? cert)))

    (define/public (lookup-by-subject dn)
      (append (hash-ref dn=>cert dn null)
              (send parent lookup-by-subject dn)))
    (define/public (lookup-by-key-id keyid)
      (append (hash-ref keyid=>cert keyid null)
              (send parent lookup-by-key-id keyid)))

    (define/public (add-certificates certs #:trusted? [trusted? #f])
      (define ((mkcons v) vs) (cons v vs))
      (define-values (dn=>cert* keyid=>cert*)
        (for/fold ([dn=>cert dn=>cert] [keyid=>cert keyid=>cert])
                  ([cert (in-list certs)])
          (values (let ([subject (send cert get-subject)])
                    (cond [(DN-not-empty? subject)
                           (hash-update dn=>cert subject (mkcons cert) null)]
                          [else dn=>cert]))
                  (cond [(send cert get-subject-key-id)
                         => (lambda (keyid)
                              (hash-update keyid=>cert keyid (mkcons cert) null))]
                        [else keyid=>cert]))))
      (define trusted-h*
        (cond [trusted?
               (for/fold ([h trusted-h]) ([cert (in-list certs)])
                 (hash-set h (send cert get-der) #t))]
              [else trusted-h]))
      (new this% (parent parent)
           (trusted-h trusted-h*)
           (dn=>cert dn=>cert*)
           (keyid=>cert keyid=>cert*)))
    ))

;; ============================================================

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

(define (DN-match? dn1 dn2)
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
     (and (= (length rdns1) (length rdns2))
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

(define (DN-not-empty? dn)
  (match dn
    [(list 'rdnSequence (? pair?)) #t]
    [_ #f]))

(define (wf-DN? dn)
  ;; FIXME: see 4.1.2.4, 4.1.2.6
  ;; -- 'modern-strings (CA-MUST), not checked, FIXME
  #t)

(define (DN-get-common-name dn)
  (match dn
    [(list 'rdnSequence rdns)
     (for/or ([rdn (in-list rdns)])
       (for/or ([av (in-list rdn)])
         (match av
           [(hash-table ['type (== id-at-commonName)] ['value cnv])
            (get-attr-value cnv (lambda (v) #f))]
           [_ #f])))]))

(define (get-attr-value ds handle-other)
  (match ds
    [(list 'printableString (? string? s)) s]
    [(list 'universalString (? string? s)) s]
    [(list 'utf8String (? string? s)) s]
    [(list 'bmpString (? string? s)) s]
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

;; ----------------------------------------

(require racket/pretty)
(pretty-print-columns 160)
(require crypto crypto/all)
(crypto-factories libcrypto-factory)

;; read-pem-chain : InputPort -> (Listof Bytes)
(define (read-pem-certs in)
  (for/list ([v (in-port (lambda (in) (read-pem in #:only '(#"CERTIFICATE"))) in)])
    (cdr v)))

(define (get-cert-chain file)
  (define ders (call-with-input-file file read-pem-certs))
  (for/fold ([obj #f]) ([der (in-list (reverse ders))])
    (new certificate% (der der) (issuer-obj obj))))
