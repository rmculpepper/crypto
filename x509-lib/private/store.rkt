;; Copyright 2020 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         racket/class
         racket/list
         racket/hash
         racket/promise
         scramble/result
         asn1
         crypto/pem
         "interfaces.rkt"
         "asn1.rkt"
         "cert.rkt"
         "chain.rkt"
         "store-os.rkt"
         "util.rkt")
(provide (all-defined-out))

;; ============================================================

;; read-pem-certificates : InputPort -> (Listof Certificate)
;; Reads up to `count` certificates (or until end of port); does not close.
(define (read-pem-certificates in
                               #:count [count +inf.0]
                               #:allow-aux? [aux? #f]
                               #:who [who 'read-pem-certificates])
  (define (read-pem-cert in)
    (read-pem in
              #:only (cons #"CERTIFICATE" (if aux? '(#"TRUSTED CERTIFICATE") '()))
              #:who who))
  (for/list ([v (in-port read-pem-cert in)] [i (in-range count)])
    (match v
      [(cons #"CERTIFICATE" der)
       (bytes->certificate der #:who who)]
      [(cons #"TRUSTED CERTIFICATE" der)
       (define in (open-input-bytes der))
       (define cert-der (begin (read-asn1 ANY in) (subbytes der 0 (file-position in))))
       (define aux (read-asn1 CertAux in))
       (certificate+aux (bytes->certificate cert-der #:who who) aux)])))

;; pem-file->certificates : PathString -> (Listof Certificate)
(define (pem-file->certificates path
                                #:count [count +inf.0]
                                #:allow-aux? [aux? #f]
                                #:who [who 'pem-file->certificates])
  (call-with-input-file* path
    (lambda (in) (read-pem-certificates in #:count count #:allow-aux? aux? #:who who))))

;; ============================================================

(define (empty-store #:security-level [security-level INIT-SECURITY-LEVEL])
  (new certificate-store% (security-level security-level)))

(define certificate-store%
  (class* object% (-certificate-store<%>)
    (init-field [trusted-h '#hash()] ;; Certificate => Trust
                [cert-h    '#hash()] ;; Certificate => #t
                [lookups   null]
                [security-level INIT-SECURITY-LEVEL])
    (super-new)

    ;; check-trust : Anchor -> (Result #t (Listof Symbol))
    (define/public (check-trust anchor)
      (define anc-trust (get-field trust anchor))
      (cond [(get-trust (get-field cert anchor))
             => (lambda (store-trust)
                  (define anc-trust (get-field trust anchor))
                  ;; Does the anchor require less trust than the store gives?
                  (cond [(trust<=? anc-trust store-trust) (ok #t)]
                        [else (bad '(anchor:insufficient-trust))]))]
            [else (bad '(anchor:not-trusted))]))

    ;; get-trust : Certificate -> #f or Trust
    (define/public (get-trust cert)
      (or (hash-ref trusted-h cert #f)
          (for/or ([lu (in-list lookups)]) (send lu get-trust cert))))

    (define/public (lookup-by-subject dn)
      (remove-duplicates
       (apply append
              (for/list ([cert (in-hash-keys cert-h)]
                         #:when (Name-equal? dn (send cert get-subject)))
                cert)
              (for/list ([lu (in-list lookups)])
                (send lu lookup-by-subject dn)))))

    (define/private (copy #:trusted-h [trusted-h trusted-h]
                          #:cert-h [cert-h cert-h]
                          #:lookups [lookups lookups]
                          #:security-level [security-level security-level])
      (new this% (trusted-h trusted-h) (cert-h cert-h)
           (lookups lookups) (security-level security-level)))

    (define/public (add #:untrusted [untrusted-certs null]
                        #:trusted [trusted-certs null])
      (-add 'add untrusted-certs trusted-certs))

    (define/private (-add who untrusted-certs trusted-certs)
      (define (add-trusted h cert trust)
        (unless (equal? (hash-ref h cert trust) trust)
          (error who "store already contains certificate with different trust\n  certificate: ~e"
                 cert))
        (hash-set h cert trust))
      (define cert-h*
        (for*/fold ([h cert-h])
                   ([certs (in-list (list untrusted-certs trusted-certs))]
                    [cert (in-list certs)])
          (match cert
            [(? certificate? cert) (hash-set h cert #t)]
            [(certificate+aux cert aux) (hash-set h cert #t)])))
      (define trusted-h*
        (for/fold ([h trusted-h])
                  ([cert (in-list trusted-certs)])
          (match cert
            [(? certificate? cert) (add-trusted h cert base-trust)]
            [(certificate+aux cert aux) (add-trusted h cert (certaux->trust aux))])))
      (copy #:trusted-h trusted-h* #:cert-h cert-h*))

    (define/public (add-lookups new-lookups)
      (copy #:lookups (append new-lookups lookups)))
    (define/public (set-security-level new-security-level)
      (cond [(eq? security-level new-security-level) this]
            [else (copy #:security-level new-security-level)]))

    (define/public (add-trusted-from-pem-file pem-file #:allow-aux? [aux? #f])
      (let ([who 'add-trusted-from-pem-file])
        (-add who null (pem-file->certificates pem-file #:allow-aux? aux?))))
    (define/public (add-trusted-from-openssl-directory dir)
      (add-lookups (list (new x509-lookup:openssl-trusted-directory% (dir dir)))))

    (define/public (add-default-trusted #:who [who 'certificate-store:add-default-trusted])
      (case (system-type)
        [(unix)
         (define-values (cert-dirs cert-files) (openssl-trust-sources who))
         (cond [(pair? cert-dirs) (add-trusted-from-openssl-directory (car cert-dirs))]
               [(pair? cert-files) (add-trusted-from-pem-file (car cert-files))]
               [error who "failed to find usable trust sources"])]
        [(macosx)
         (define cert-der-list (macos-trust-anchors who))
         (add #:trusted (map bytes->certificate cert-der-list))]
        [(windows)
         (define cert-der-list (win32-trust-anchors who "ROOT"))
         (add #:trusted (map bytes->certificate cert-der-list))]))

    ;; ----------------------------------------
    ;; Chain Building

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
      (define store* (add #:untrusted other-untrusted-certs))
      (define pre-chains (send store* build-pre-chains end-cert))
      (unless (or (pair? pre-chains) empty-ok?)
        (raise-incomplete-chain-error who end-cert))
      (validate-chains pre-chains valid-time #:empty-ok? empty-ok? #:who who))

    ;; build-pre-chains : Cert -> (Listof PreChain)
    (define/public (build-pre-chains cert)
      ;; loop : (Listof (U PreChain (Listof Cert))) -> (Listof PreChain)
      (define (loop worklist)
        (define-values (pcs incomplete) (partition pre-chain? worklist))
        (append pcs (if (pair? incomplete) (loop (extend incomplete)) null)))
      ;; extend : (Listof (Listof Cert)) -> (Listof (U PreChain (Listof Cert)))
      (define (extend incomplete)
        (append*
         (for/list ([partial (in-list incomplete)])
           (match-define (cons cert kcerts) partial)
           (cond [(get-trust cert)
                  => (lambda (trust) (list (make-pre-chain cert trust kcerts)))]
                 [else
                  (define issuer-name (send cert get-issuer))
                  (define issuer-certs (lookup-by-subject issuer-name))
                  (for/list ([issuer-cert (in-list issuer-certs)]
                             #:when (not (member issuer-cert partial)))
                    (cons issuer-cert partial))]))))
      ;; ----
      (loop (list (list cert))))

    ;; make-pre-chain : Cert Trust (Listof Cert) -> PreChain
    (define/private (make-pre-chain cert trust kcerts)
      (for/fold ([pc (make-anchor-chain cert trust)])
                ([kcert (in-list kcerts)])
        (send pc extend-chain kcert)))

    ;; validate-chains : (Listof PreChain) -> (Listof CertificateChain)
    ;; Discards invalid chains, returns certificate-chain% objects for valid.
    (define/public (validate-chains pre-chains [valid-time (current-seconds)]
                                    #:empty-ok? [empty-ok? #f]
                                    #:who [who 'validate-chains])
      (define chains ;; (Listof CertificateChain)
        (match (filter-results
                #:empty-ok? empty-ok?
                (for/list ([pre-chain (in-list pre-chains)])
                  (send pre-chain get-validation-result)))
          [(ok chains) chains]
          [(bad (cons errs _))
           (raise-invalid-chain-error who errs)]))
      (define trusted-chains ;; (Listof CertificateChain)
        (match (filter-results
                #:empty-ok? empty-ok?
                (for/list ([chain (in-list chains)])
                  (match (send chain check-trust this valid-time
                               #:security-level security-level)
                    [(ok #t) (ok chain)]
                    [(bad errs) (bad errs)])))
          [(ok chains) chains]
          [(bad (cons errs _))
           (raise-invalid-chain-error who errs)]))
      trusted-chains)

    ;; -test-candidate-chain : (Listof Cert) -> CertificateChain
    (define/public (-test-candidate-chain cert-list)
      (define pc (make-pre-chain (car cert-list) base-trust (cdr cert-list)))
      (car (validate-chains (list pc) #:who '-test-candidate-chain)))

    ;; ----------------------------------------

    (define/public (pem-file->chain pem-file [valid-time (current-seconds)]
                                    #:who [who 'pem-file->chain])
      (define certs (pem-file->certificates pem-file #:who who))
      (unless (pair? certs) (error who "no certificates found in file\n  file: ~e" pem-file))
      (build-chain (car certs) certs valid-time #:who who))
    ))

(define (raise-invalid-chain-error who errs)
  (let/ec escape
    (define msg (format "~s: chain validation failed\n  errors: ~e" who errs))
    (raise (exn:x509:chain msg (continuation-marks escape) errs))))
(define (raise-incomplete-chain-error who end-cert)
  (let/ec escape
    (define msg (format "~s: failed to build complete chain\n  end certificate: ~e" who end-cert))
    (raise (exn:x509:chain msg (continuation-marks escape) '(incomplete)))))

;; ----------------------------------------

(define x509-lookup:openssl-trusted-directory%
  (class* object% (x509-lookup<%>)
    (init-field dir)
    (super-new)

    ;; trusted-cache : WeakHasheq[Certificate => Trust]
    (define trusted-cache (make-weak-hasheq))

    ;; get-trust : Certificate -> #f or Trust
    (define/public (get-trust cert)
      (or (hash-ref trusted-cache cert #f)
          (for/or ([trusted (in-list (lookup-by-subject (send cert get-subject)))])
            (and (equal? trusted cert) base-trust))))

    (define/public (lookup-by-subject name)
      (define (padto n s) (string-append (make-string (- n (string-length s)) #\0) s))
      (define base (padto 8 (number->string (openssl-Name-hash name) 16)))
      (let loop ([i 0])
        (define file (build-path dir (format "~a.~a" base i)))
        (cond [(file-exists? file)
               (define cert (read-cert-from-file file))
               (cond [(and cert (Name-equal? name (send cert get-subject)))
                      (hash-set! trusted-cache cert base-trust)
                      (cons cert (loop (add1 i)))]
                     [else (loop (add1 i))])]
              [else null])))

    (define/public (clear-cache!)
      (hash-clear! trusted-cache))

    ;; FIXME: cache reads?

    (define/private (read-cert-from-file file)
      (match (pem-file->certificates file)
        [(list cert) cert]
        [_ (begin0 #f (log-x509-error "bad certificate PEM file: ~e" file))]))
    ))

;; ----------------------------------------

(define default-store-p
  (let ([base-store (empty-store)])
    (delay/sync (send base-store add-default-trusted #:who 'default-store))))

;; default-store : -> CertificateStore
(define (default-store #:security-level [security-level INIT-SECURITY-LEVEL])
  (send (force default-store-p) set-security-level security-level))
