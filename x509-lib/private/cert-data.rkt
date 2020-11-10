#lang racket/base
(require racket/match
         racket/class
         racket/list
         racket/string
         racket/date
         asn1
         "interfaces.rkt"
         "asn1.rkt"
         "stringprep.rkt")
(provide (all-defined-out))

;; ============================================================

(define certificate-data%
  (class* object% (certificate-data<%>)
    (init-field der)
    (super-new)

    (define/public (get-der) der)

    (define cert (bytes->asn1 Certificate der))
    (define tbs (hash-ref cert 'tbsCertificate))

    (define/public (equal-to other [recur equal?])
      (equal? (get-der) (send other get-der)))
    (define/public (hash-code recur)
      (recur (get-der)))
    (define/public (custom-write out mode)
      (fprintf out "#<certificate: ~a>" (Name->string (get-subject))))

    (define/public (get-cert-signature-alg)
      (hash-ref cert 'signatureAlgorithm))
    (define/public (get-cert-signature-bytes)
      (match (hash-ref cert 'signature)
        [(bit-string sig-bytes 0) sig-bytes]))
    ;;(define/public (get-cert-tbs) tbs)

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

    (define/public (get-subject-common-names)
      (match (get-subject)
        [(list 'rdnSequence rdns)
         (for*/list ([rdn (in-list rdns)] [av (in-list rdn)]
                     #:when (equal? (hash-ref av 'type) id-at-commonName))
           (get-attr-value (hash-ref av 'value) values))]))

    (define/public (is-CA?)
      (cond [(get-extension id-ce-basicConstraints)
             => (lambda (ext) (hash-ref (extension-value ext) 'cA))]
            [else #f]))
    (define/public (is-CRL-issuer?) (and (memq 'cRLSign (get-key-uses)))) ;; FIXME: and (is-CA?)
    (define/public (is-self-issued?) ;; 6.1
      (let ([subject (get-subject)] [issuer (get-issuer)])
        (Name-equal? subject issuer)))
    (define/public (is-self-signed?)
      ;; FIXME
      #f)

    (define/public (get-key-uses)
      (cond [(get-extension id-ce-keyUsage) => extension-value] [else null]))
    (define/public (ok-key-use? use [default #f])
      (cond [(get-extension id-ce-keyUsage)
             => (lambda (ext) (and (memq use (extension-value ext)) #t))]
            [else (if (procedure? default) (default) default)]))

    (define/public (can-cert-sign?)
      (ok-key-use? 'keyCertSign (is-CA?)))

    (define/public (get-extended-key-uses)
      (cond [(get-extension id-ce-extKeyUsage) => extension-value] [else null]))
    (define/public (ok-extended-key-use? use-oid [default #f] [allow-any? #t])
      (cond [(get-extension id-ce-extKeyUsage)
             => (lambda (ext)
                  (define uses (extension-value ext))
                  (or (and (member use-oid uses) #t)
                      (and allow-any? (member anyExtendedKeyUsage uses) #t)))]
            [else (if (procedure? default) (default) default)]))

    (define/public (get-extension id)
      (for/or ([ext (in-list (get-extensions))] #:when (equal? id (extension-id ext))) ext))
    (define/public (get-extension-value id default)
      (cond [(get-extension id) => extension-value] [else default]))

    (define/public (get-name-constraints)
      (get-extension-value id-ce-nameConstraints #f))
    (define/public (get-subject-alt-name [kind #f])
      (define altnames (get-extension-value id-ce-subjectAltName null))
      (cond [kind (for/list ([altname (in-list altnames)] #:when (eq? kind (car altname)))
                    (cadr altname))]
            [else altnames]))

    (define/public (get-validity-seconds)
      (match (get-validity)
        [(hash-table ['notBefore ok-start] ['notAfter ok-end])
         (list (asn1-time->seconds ok-start) (asn1-time->seconds ok-end))]))
    ))

;; ============================================================

;; FIXME: generalize, move to asn1-lib as util module?
(define (asn1-time->seconds t)
  (define (map-num ss) (map string->number ss))
  (match t
    [(list 'utcTime
           (regexp #px"^([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z$"
                   (cons _ (app map-num (list YY MM DD hh mm ss)))))
     ;; See 4.1.2.5.1 for interpretation.
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
