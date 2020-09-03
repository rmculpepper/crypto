#lang racket/base
(require racket/match
         racket/class
         racket/list
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

(define certificate<%>
  (interface*
   ()
   ([prop:equal+hash
     (list (lambda (self other recur) (send self equal-to other recur))
           (lambda (self recur) (send self hash-code recur))
           (lambda (self recur) (send self hash-code recur)))])
   equal-to
   hash-code))

(define certificate%
  (class* object% (certificate<%>)
    (init-field der)
    (super-new)

    (define/public (get-der) der)

    (define cert (bytes->asn1 Certificate der))
    (define tbs (hash-ref cert 'tbsCertificate))

    (define/public (equal-to other recur)
      (equal? (get-der) (send other get-der)))
    (define/public (hash-code recur)
      (recur (get-der)))

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
        (Name-match? subject issuer)))
    (define/public (is-self-signed?)
      ;; FIXME
      #f)
    (define/public (get-key-uses)
      (cond [(get-extension id-ce-keyUsage) => extension-value] [else null]))

    (define/public (get-extension id)
      (for/or ([ext (in-list (get-extensions))] #:when (equal? id (extension-id ext))) ext))
    (define/public (get-extension-value id default)
      (cond [(get-extension id) => extension-value] [else default]))

    (define/public (get-name-constraints)
      (get-extension-value id-ce-nameConstraints #f))
    (define/public (get-subject-alt-name)
      (get-extension-value id-ce-subjectAltName null))

    ;; An error symbol should read as a true statement about the certificate
    ;; that points out a fault, rather than reading as a desired property that
    ;; the certificate fails to hold.
    (define errors null) ;; (Listof Symbol), mutated
    (define/public (get-errors) errors)

    ;; Checks that the certificate is well-formed, without regard for other
    ;; certificates in the chain. (For example, the signature is not verified.)
    (let ()
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
            (bad! 'authority-key-id:missing)))
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
        (unless (Name-match? (get-issuer) (send issuer get-subject))
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
        (when (pair? errors) (add-error errors)))
      ;; 6.1.5
      (when final-in-path?
        ;; 6.1.5 (a,b) explicit-policy, policies
        (void 'POLICIES-UNSUPPORTED)
        ;; 6.1.5 (c-e) handled by get-pk method instead
        (void 'OK)
        ;; 6.1.5 (f) process other critical extensions: errors gathered in construction
        (when (pair? errors) (add-error errors))
        ;; 6.1.5 (g) policies ...
        (void 'POLICIES-UNSUPPORTED))
      (void))

    ))

(define certificate-chain%
  (class object%
    ;; chain : (list trust-anchor<%> certificate% ...+)
    ;; Note: In 6.1, trust anchor is not considered part of chain.
    (init-field chain)
    (super-new)

    (define N (length (cdr chain))) ;; don't count trust anchor

    (define/public (get-chain) chain)
    (define/public (get-end-certificate) (last chain))
    (define/public (get-trust-anchor) (first chain))

    (define/public (validate-chain [store root])
      ;; Note: this does not verify that the end certificate is valid for
      ;; any particular *purpose*.
      (define vi (new validation% (N N)))
      (when store
        (define ta (get-trust-anchor))
        (cond [(not (is-a? ta certificate%))
               (send vi add-error (cons 0 'trust-anchor:not-certificate))]
              [(not (send store trust? ta))
               (send vi add-error (cons 0 'trust-anchor:not-trusted))]
              [else (void)]))
      (for ([issuer (in-list chain)]
            [cert (in-list (cdr chain))]
            [index (in-naturals 1)])
        (send cert check-link-in-chain index issuer vi (= index N)))
      (send vi get-errors))

    ))

;; Note: for documentation; not actually implemented
(define trust-anchor<%>
  (interface ()
    get-pk
    get-subject
    ))

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

;; build-chains : certificate% x509-store<%> -> (Listof certificate-chain%)
(define (build-chains end-cert [other-untrusted-certs null] #:store [store0 root])
  (define store (send store0 add-certificates other-untrusted-certs #:trusted? #f))
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

(define x509-store<%>
  (interface ()
    trust?            ;; certificate% -> Boolean
    lookup-by-subject ;; DN -> (Listof certificate%)
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

    (define/public (lookup-by-subject/hash dn)
      (define (padto n s) (string-append (make-string (- n (string-length s)) #\0) s))
      (define base (padto 8 (number->string (dn-hash (asn1->bytes Name dn)) 16)))
      (let loop ([i 0])
        (define file (build-path dir (format "~a.~a" base i)))
        (cond [(file-exists? file)
               (define cert (read-cert-from-file file))
               (if (Name-match? dn (send cert get-subject))
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
    (define/public (add-certificates certs #:trusted? [trusted? #f])
      (send (new x509-store% (parent this))
            add-certificates certs #:trusted? trusted?))
    ))

(define x509-store%
  (class* object% (x509-store<%>)
    (init-field parent
                [trusted-h   '#hash()]
                [dn=>cert    '#hash()])
    (super-new)

    (define/public (trust? cert)
      (or (hash-ref trusted-h (send cert get-der) #f)
          (send parent trust? cert)))

    (define/public (lookup-by-subject dn)
      (append (hash-ref dn=>cert dn null)
              (send parent lookup-by-subject dn)))

    (define/public (add-certificates certs #:trusted? [trusted? #f])
      (define ((mkcons v) vs) (cons v vs))
      (define dn=>cert*
        (for/fold ([dn=>cert dn=>cert])
                  ([cert (in-list certs)])
          (let ([subject (send cert get-subject)])
            (cond [(not (Name-empty? subject))
                   (hash-update dn=>cert subject (mkcons cert) null)]
                  [else dn=>cert]))))
      (define trusted-h*
        (cond [trusted?
               (for/fold ([h trusted-h]) ([cert (in-list certs)])
                 (hash-set h (send cert get-der) #t))]
              [else trusted-h]))
      (new this% (parent parent)
           (trusted-h trusted-h*)
           (dn=>cert dn=>cert*)))
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

;; ----------------------------------------

(require racket/pretty)
(pretty-print-columns 160)
(require crypto crypto/all)
(crypto-factories libcrypto-factory)

;; read-pem-chain : InputPort -> (Listof Bytes)
(define (read-pem-certs in)
  (for/list ([v (in-port (lambda (in) (read-pem in #:only '(#"CERTIFICATE"))) in)])
    (cdr v)))

(define (read-certs file)
  (define ders (call-with-input-file file read-pem-certs))
  (map (lambda (der) (new certificate% (der der))) ders))

(define (read-chain file)
  (define certs (read-certs file))
  (car (build-chains (car certs) (cdr certs))))
