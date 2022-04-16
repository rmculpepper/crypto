;; Copyright 2020 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/class
         racket/match
         racket/list
         racket/hash
         racket/serialize
         scramble/result
         crypto
         "interfaces.rkt"
         "asn1.rkt"
         (submod "asn1.rkt" verify)
         "cert.rkt"
         "util.rkt")
(provide (all-defined-out))

;; References:
;; - RFC 5280 (https://tools.ietf.org/html/rfc5280)
;; - RFC 6818 (general updates) (https://tools.ietf.org/html/rfc6818)
;; - RFC 8398 and 8399 (Internationalization) (https://tools.ietf.org/html/rfc8398,
;;   https://tools.ietf.org/html/rfc8399)
;; - CA/Browser Forum Baseline Recommendations (v1.7.3)

;; ============================================================

;; A CertificateChain is an instance of certificate-chain% (or its subclass
;; certificate-anchor%).

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
  (class* object% (certificate-chain<%>)
    (init-field issuer-chain  ;; Chain or #f if anchor
                cert)         ;; Certificate
    (super-new)

    (define/public (get-issuer-chain) issuer-chain)
    (define/public (get-certificate) cert)
    (define/public (get-certificates)
      (cons cert (if issuer-chain (send issuer-chain get-certificates) null)))
    (define/public (get-issuer-chain-or-self) (or issuer-chain this))
    (define/public (get-issuer-or-self)
      (send (get-issuer-chain-or-self) get-certificate))
    (define/public (get-anchor)
      (if issuer-chain (send issuer-chain get-anchor) this))
    (define/public (is-anchor?) (not issuer-chain))

    (define/public (get-subject) (send cert get-subject))
    (define/public (get-subject-alt-names [kind #f])
      (send cert get-subject-alt-names kind))
    (define/public (get-spki) (send cert get-spki))

    ;; ----------------------------------------

    ;; pubkey-cache : WeakHasheq[Factory/s => pk-key?]
    ;; The factories can change; cache for current factories.
    (define pubkey-cache (make-weak-hasheq))

    (define/public (get-public-key [factories (crypto-factories)])
      (hash-ref! pubkey-cache factories (lambda () (-get-public-key factories))))

    (define/private (-get-public-key factories)
      (parameterize ((crypto-factories factories))
        (datum->pk-key (get-spki) 'SubjectPublicKeyInfo)))

    ;; check-signature : (U Bytes AlgorithmIdentifier) Bytes Bytes
    ;;                -> (Result #t (Listof Symbol))
    (define/public (check-signature algid tbs sig
                                    #:factories [factories (crypto-factories)])
      (check-signature/algid (get-public-key factories) algid tbs sig))

    ;; ----------------------------------------
    ;; Validity of Self Chain

    ;; get-index : -> Nat  -- 0 is anchor
    (define/public (get-index) index)

    (define index (if issuer-chain (add1 (send issuer-chain get-index)) 0))

    ;; get-max-path-length : -> Integer or #f
    ;; The maximum number of *intermediate* certificates that can *follow* this one.
    ;; Thus if zero, can still extend with end certificate but not new intermediate.
    ;; If less than zero, cannot extend; but -1 is okay for end certificate.
    (define/public (get-max-path-length) max-path-length)

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

    ;; get-validity-seconds : -> (list Seconds Seconds)
    (define/public (get-validity-seconds)
      (list valid-from-time valid-to-time))

    ;; valid-{from,to}-time : Seconds
    (define-values (valid-from-time valid-to-time)
      (match (send cert get-validity-seconds)
        [(list cert-from cert-to)
         (match (and issuer-chain (send issuer-chain get-validity-seconds))
           [(list issuer-from issuer-to)
            (values (max cert-from issuer-from) (min cert-to issuer-to))]
           [#f (values cert-from cert-to)])]))

    ;; ok-validity-period? : Seconds [Seconds] -> Boolean
    (define/public (ok-validity-period? [from-time (current-seconds)] [to-time from-time])
      (ok? (check-validity-period from-time to-time)))

    ;; check-validity-period : Real Real -> (Result #t (Listof Nat Symbol))
    (define/public (check-validity-period from-time to-time)
      (match-define (list ok-start ok-end) (get-validity-seconds))
      (if (<= ok-start from-time to-time ok-end)
          (ok #t)
          (append-results
           (bad (list (cons index 'validity-period:not-contained)))
           (cond [issuer-chain (send issuer-chain check-validity-period from-time to-time)]
                 [else (ok #t)]))))

    ;; ----------------------------------------
    ;; Security Level of Self Chain

    (define/public (get-security-level)
      (security-strength->level (get-security-strength)))

    (define/public (get-security-strength)
      (define (min* x y) (if (and x y) (min x y) (or x y)))
      (min* (get-public-key-security-strength)
            (and issuer-chain
                 (min* (or (get-signature-security-strength #f) 0)
                       (send issuer-chain get-security-strength)))))

    (define/public (get-public-key-security-strength)
      (send (get-public-key) get-security-bits))
    (define/public (get-signature-security-strength)
      (define-values (algid _tbs _sig) (send cert get-signature-info))
      (sig-alg-security-strength algid))

    ;; check-security-strength : Nat -> (Result #t (Listof (cons Nat Symbol)))
    (define/public (check-security-strength target-secbits)
      (append-results
       (cond [(>= (get-public-key-security-strength) target-secbits) (ok #t)]
             ;; Note: here index means owner of public key.
             [else (bad (list (cons index 'security-level:weak-public-key)))])
       (cond [issuer-chain
              (append-results
               (let ([sig-secbits (get-signature-security-strength #f)])
                 (cond [(or (eq? sig-secbits #f) (>= sig-secbits target-secbits)) (ok #t)]
                       ;; Note: here index means site of signature (created by issuer!).
                       [else (bad (list (cons index 'security-level:weak-signature-algorithm)))]))
               (send issuer-chain check-security-strength target-secbits))]
             [else (ok #t)])))

    ;; check-security-level : Nat[0-5] -> (Result #t (Listof (cons Nat Symbol)))
    (define/public (check-security-level level)
      (check-security-strength (security-level->strength level)))

    ;; ----------------------------------------
    ;; Trusted

    ;; trusted? : Store/#f Seconds Seconds -> Boolean
    (define/public (trusted? store [from-time (current-seconds)] [to-time from-time]
                             #:security-level [security-level INIT-SECURITY-LEVEL])
      (ok? (check-trust store from-time to-time #:security-level security-level)))

    ;; check-trust : Store/#f Seconds Seconds -> (Result #t (Listof (cons Nat Symbol)))
    (define/public (check-trust store [from-time (current-seconds)] [to-time from-time]
                                #:security-level [security-level INIT-SECURITY-LEVEL])
      (define (add-index0 v) (cons 0 v))
      (append-results
       (if store (bad-map add-index0 (send store check-trust (get-anchor))) (ok #t))
       (check-security-level security-level)
       (check-self-as-final)
       (check-validity-period from-time to-time)))

    ;; ----------------------------------------
    ;; Purposes of Self Chain

    (define/public (ok-key-usage? use [default #f])
      (send cert ok-key-usage? use default))

    (define/public (ok-extended-key-usage? eku [on-unset #f] #:recur [recur? #t])
      ;; FIXME: might want to generalize #:recur to support other rules?
      (cond [recur?
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
             (define result (foldr join 'unset (get-extended-key-usage-chain eku)))
             (case result [(yes) #t] [(no) #f] [else on-unset])]
            [else (case (get-extended-key-usage eku)
                    [(yes) #t] [(no) #f] [else on-unset])]))

    ;; get-extended-key-usage-chain : OID -> (Listof (U 'yes 'no 'unset)), leaf first, root CA last
    (define/public (get-extended-key-usage-chain eku)
      (cons (get-extended-key-usage eku)
            (if issuer-chain (send issuer-chain get-extended-key-usage-chain eku) '())))

    ;; get-extended-key-usage : OID -> (U 'yes 'no 'unset)
    ;; Note: overridden by trust-anchor%
    (define/public (get-extended-key-usage eku)
      (send cert get-extended-key-usage eku))

    ;; ----------------------------------------
    ;; Chain Extension

    ;; extension-cache : Hasheq[Certificate => PreChain]
    (define extension-cache (make-weak-hasheq))

    ;; extend-chain : Certificate -> PreChain
    (define/public (extend-chain new-cert)
      (hash-ref! extension-cache new-cert (lambda () (-extend-chain new-cert))))

    (define/private (-extend-chain new-cert)
      (define result
        (append-results (check-self-as-intermediate)
                        (check-certificate-as-addition new-cert)
                        (get-validation-result)))
      (match result
        [(ok _) (new certificate-chain% (issuer-chain this) (cert new-cert))]
        [(? bad?) (new bad-chain% (issuer-chain this) (cert new-cert)
                       (validation-result result))]))

    ;; get-validation-result : -> (Result CertificateChain (Listof (cons Nat Any)))
    (abstract get-validation-result)

    ;; check-self-as-intermediate : -> (Result #t (Listof (cons Nat Symbol)))
    (define/public (check-self-as-intermediate)
      (define (add-index what) (cons (get-index) what))
      ;; 6.1.4
      (append-results
       ;; 6.1.4 (a-b) policy-mappings, policies, ...
       #| POLICIES NOT SUPPORTED |#
       ;; 6.1.4 (c-f) handled by get-public-key method instead
       ;; 6.1.4 (g) name constraints -- in constructor
       ;; 6.1.4 (h, l) decrement counters -- in constructor
       (cond [(>= (or max-path-length +inf.0) 0) (ok #t)]
             [else (bad (list (add-index 'intermediate:max-path-length)))])
       ;; 6.1.4 (i, j) policy-mapping, inhibit-anypolicy, ...
       #| POLICIES NOT SUPPORTED |#
       ;; 6.1.4 (k) check CA (reject if no basicConstraints extension)
       (cond [(send cert is-CA?) (ok #t)]
             [else (bad (list (add-index 'intermediate:not-CA)))])
       ;; 6.1.4 (m) -- in constructor
       ;; 6.1.4 (n)
       (cond [(send cert ok-key-usage? 'keyCertSign #t) (ok #t)]
             [else (bad (list (add-index 'intermediate:missing-keyCertSign)))])
       ;; 6.1.4 (o) process other critical extensions: errors gathered in construction
       #| checked in certificate% |#))

    ;; check-self-as-final : -> (Result #t (Listof (cons Nat Symbol)))
    (define/public (check-self-as-final)
      (append-results
       ;; 6.1.3 (b,c) -- deferred
       (cond [issuer-chain (send issuer-chain check-certificate-name-constraints cert)]
             [else (ok #t)])
       ;; 6.1.5
       ;; 6.1.5 (a,b) explicit-policy, policies
       #| POLICIES NOT SUPPORTED |#
       ;; 6.1.5 (c-e) handled by get-public-key method instead
       ;; 6.1.5 (f) process other critical extensions: errors gathered in construction
       ;; 6.1.5 (g) policies ...
       #| POLICIES NOT SUPPORTED |#))

    ;; ------------------------------------------
    ;; Self-as-CA Operations

    ;; check-certificate-as-addition : Certificate -> (Result #t (Listof (cons Nat Any)))
    (define/public (check-certificate-as-addition new-cert)
      (define (add-index what) (cons (add1 index) what))
      ;; 6.1.3
      (append-results
       ;; 6.1.3 (a)(1) verify signature
       (bad-map add-index (check-certificate-signature new-cert))
       ;; 6.1.3 (a)(2) currently valid
       (match (send new-cert get-validity-seconds)
         [(list cert-from cert-to)
          (cond [(<= (max valid-from-time cert-from) (min valid-to-time cert-to)) (ok #t)]
                [else (bad (list (add-index 'validity-period:empty-intersection)))])])
       ;; 6.1.3 (a)(3) (not revoked)
       #| CRL checked separately |#
       ;; 6.1.3 (a)(4) issuer
       (cond [(Name-equal? (send new-cert get-issuer) (get-subject)) (ok #t)]
             [else (bad (list (add-index 'issuer:name-mismatch)))])
       ;; 6.1.3 (b,c) check name constraints
       (cond [(send new-cert is-self-issued?)
              ;; Check self-issued cert's name constraints only if final.
              ;; So skip now, add to check-for-final
              (ok #t)]
             [else (bad-map add-index (check-certificate-name-constraints new-cert))])
       ;; 6.1.3 (d-f) process policies; set/check valid-policy-tree, explicit-policy
       #| POLICIES NOT SUPPORTED |#))

    ;; check-certificate-signature : Cert -> (Result #t (Listof Symbol))
    (define/public (check-certificate-signature new-cert)
      (define-values (algid tbs-der sig) (send new-cert get-signature-info))
      (check-signature algid tbs-der sig))

    ;; check-certificate-name-constraints : Cert -> (Result #t (Listof (cons Nat Symbol)))
    (define/public (check-certificate-name-constraints new-cert)
      (define subject-name (send new-cert get-subject))
      (define alt-names (send new-cert get-subject-alt-names))
      (append-results
       (check-name-constraints (list 'directoryName subject-name) 'subject)
       (append*-results
        (match subject-name
          [(list 'rdnSequence rdns)
           (for*/list ([rdn (in-list rdns)]
                       [av (in-list rdn)]
                       #:when (equal? (hash-ref av 'type) id-emailAddress))
             (check-name-constraints (list 'rfc822Name (hash-ref av 'value)) 'subject-email))]))
       (append*-results
        (for/list ([san (in-list alt-names)])
          (check-name-constraints san 'alt)))))

    ;; name-constraints : ParsedNameConstraints
    ;; Only from the current certificate; see recursive check-name-constraints.
    ;; 6.1.4 (g) name constraints
    (define name-constraints
      (cond [(send cert get-name-constraints)
             => (lambda (ncs) (parse-name-constraints index ncs))]
            [else null]))

    ;; check-name-constraints : GeneralName Symbol -> (Result #t (Listof (cons Nat Symbol)))
    ;; Check the given name against the constraints of this certificate and issuer chain.
    (define/public (check-name-constraints gname kind)
      ;; 6.1.4 (g) name constraints
      (append-results
       (cond [(name-constraints-name-ok? name-constraints gname) (ok #t)]
             [else
              (bad (case kind
                     [(subject) (list (cons index 'name-constraints:subject-rejected))]
                     [(subject-email) (list (cons index 'name-constraint:subject-email-rejected))]
                     [else (list (cons index 'name-constraints:subjectAltName-rejected))]))])
       (if issuer-chain (send issuer-chain check-name-constraints gname kind) (ok #t))))

    ;; ----------------------------------------
    ;; Checking suitability for a purpose

    (define/public (suitable-for-CA?)
      (ok? (check-self-as-intermediate)))

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
          (and (ok-extended-key-usage? id-kp-OCSPSigning #f #:recur #f)
               (send (get-issuer-or-self) has-same-public-key? for-ca-cert))))

    (define/public (suitable-for-tls-server? host)
      (ok? (check-suitable-for-tls-server host)))

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
      (append-results
       (cond [(for/or ([use (in-list tls-key-usages)]) (ok-key-usage? use #t)) (ok #t)]
             [else (bad '(tls:missing-key-usage))])
       (cond [(ok-extended-key-usage? id-kp-serverAuth #f) (ok #t)]
             [else (bad '(tls:missing-serverAuth-eku))])
       (cond [(or (not host)
                  (for/or ([pattern (in-list (get-subject-alt-names 'dNSName))])
                    (host-matches? host pattern))
                  (and USE-CN?
                       (for/or ([cn (in-list (send cert get-subject-common-names))])
                         (and cn (host-matches? host cn)))))
              (ok #t)]
             [else (bad '(tls:host-mismatch))])))

    (define/public (suitable-for-tls-client? name)
      (ok? (check-suitable-for-tls-client name)))

    (define/public (check-suitable-for-tls-client name)
      (append-results
       (cond [(for/or ([use (in-list tls-key-usages)]) (ok-key-usage? use #t)) (ok #t)]
             [else (bad '(tls:missing-key-usage))])
       (cond [(ok-extended-key-usage? id-kp-clientAuth #f) (ok #t)]
             [else (bad '(tls:missing-clientAuth-eku))])
       (cond [(or (not name)
                  (GeneralName-equal? name (list 'directoryName (get-subject)))
                  (for/or ([altname (in-list (get-subject-alt-names #f))])
                    (GeneralName-equal? name altname)))
              (ok #t)]
             [else (bad '(tls:name-mismatch))])))
    ))

;; tls-key-usages is approximation; actually depends on TLS cipher negotiated
(define tls-key-usages '(digitalSignature keyEncipherment keyAgreement))

;; ============================================================

;; (define serializable-chain<%>
;;   (interface*
;;    ()
;;    ([prop:serializable
;;      (make-serialize-info (lambda (c) (send c -serialize))
;;                           #'deserialize-info:certificate-chain%
;;                           #f
;;                           (or (current-load-relative-directory)
;;                               (current-directory)))])))

;; (define deserialize-info:certificate-chain%
;;   (make-deserialize-info
;;    (match-lambda*
;;      [(list 'chain issuer-chain cert)
;;       (send issuer-chain extend-chain cert)]
;;      [(list 'anchor cert tm)
;;       (make-anchor-chain cert tm)])
;;    (lambda () (error 'deserialize-certificate-chain "cycles not allowed"))))

;; ============================================================

(define certificate-chain%
  (class* pre-chain% (-certificate-chain<%> writable<%> #;serializable-chain<%>)
    (inherit-field issuer-chain cert)
    (super-new)

    (define/override (get-validation-result) (ok this))

    (define/public (custom-write out)
      (fprintf out "#<certificate-chain: ~a>" (send cert get-subject-name-string)))
    (define/public (custom-display out) (custom-write out))

    ;; (define/public (-serialize)
    ;;   (vector 'chain issuer-chain cert))
    ))

;; ============================================================

(define certificate-anchor%
  (class* certificate-chain% (-trust-anchor<%>)
    (inherit-field cert)
    (init-field trust) ;; Trust
    (super-new (issuer-chain #f))

    ;; get-extended-key-usage : OID -> (U 'yes 'no 'unset)
    (define/override (get-extended-key-usage eku)
      (or (trust-lookup-eku trust eku)
          (super get-extended-key-usage eku)))

    (define/override (custom-write out)
      (fprintf out "#<certificate-anchor: ~.a>" (send cert get-subject-name-string)))

    ;; (define/override (-serialize)
    ;;   (vector 'anchor cert trust))
    ))

(define (make-anchor-chain cert trust)
  (new certificate-anchor% (cert cert) (trust trust)))

;; ----------------------------------------
;; Trust Modification

;; base-trust : Trust, means "trust according to cert contents", overriding nothing
(define base-trust (trustmod #f '#hash()))
(define allow-all-trust (trustmod (hash anyExtendedKeyUsage #t) '#hash()))
(define reject-all-trust (trustmod #f (hash anyExtendedKeyUsage #t)))

;; trust-lookup-eku : Trust EKU -> (U #f (U 'yes 'no)), #f means not overridden
(define (trust-lookup-eku tm eku)
  (match-define (trustmod replace-ekus reject-ekus) tm)
  (define (has-eku? h eku) (or (hash-ref h eku #f) (hash-ref h anyExtendedKeyUsage #f)))
  (cond [(has-eku? reject-ekus eku) 'no]
        [replace-ekus (if (has-eku? replace-ekus eku) 'yes 'no)]
        [else #f]))

;; norm-trust : TrustMod -> Trust
(define (norm-trust tm)
  (match-define (trustmod replace-ekus reject-ekus) tm)
  (cond [(hash-ref reject-ekus anyExtendedKeyUsage #f) reject-all-trust]
        [(and replace-ekus (hash-ref replace-ekus anyExtendedKeyUsage #f))
         (if (hash-empty? reject-ekus) allow-all-trust tm)]
        [else tm]))

;; certaux->trust : CertAux -> Trust
(define (certaux->trust aux)
  (define (list->hashset xs)
    (for/fold ([h '#hash()]) ([x (in-list xs)]) (hash-set h x #t)))
  (define replace-ekus (hash-ref aux 'trust #f))
  (define reject-ekus (hash-ref aux 'reject null))
  (norm-trust
   (trustmod (and replace-ekus (list->hashset replace-ekus))
             (list->hashset reject-ekus))))

;; trust<=? : Trust Trust -> Boolean
;; If an anchor has Trust `anc` and a store assigns that certificate `sto`,
;; should the store accept the anchor as trusted?
(define (trust<=? anc sto)
  (match-define (trustmod anc-replace anc-reject) anc)
  (match-define (trustmod sto-replace sto-reject) sto)
  (define (has-eku? h eku) (or (hash-ref h eku) (hash-ref h anyExtendedKeyUsage)))
  (and
   ;; If the anchor trusts something, the store must also trust it, either
   (or
    ;; (1) because neither overrides cert ekus:
    (and (eq? anc-replace #f) (eq? sto-replace #f))
    ;; (2) or anchor trust list is subset of store trust list
    (for/and ([eku (in-hash-keys anc-replace)]) (has-eku? sto-replace eku)))
   ;; If the store rejects something, the anchor must also reject it.
   (for/and ([eku (in-hash-keys sto-reject)]) (has-eku? anc-reject eku))))

;; ============================================================

(define bad-chain%
  (class pre-chain%
    (inherit-field issuer-chain)
    (init-field validation-result)
    (super-new)
    (define/override (get-validation-result) validation-result)))
