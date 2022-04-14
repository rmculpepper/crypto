;; Copyright 2020 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         racket/class
         racket/list
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
(define (read-pem-certificates in #:count [count +inf.0] #:who [who 'read-pem-certificates])
  (define (read-pem-cert in) (read-pem in #:only '(#"CERTIFICATE") #:who who))
  (for/list ([v (in-port read-pem-cert in)] [i (in-range count)])
    (define der (cdr v))
    (bytes->certificate der #:who who)))

;; pem-file->certificates : PathString -> (Listof Certificate)
(define (pem-file->certificates path #:count [count +inf.0] #:who [who 'pem-file->certificates])
  (call-with-input-file* path
    (lambda (in) (read-pem-certificates in #:count count #:who who))))

;; ============================================================

(define (empty-store #:security-level [security-level INIT-SECURITY-LEVEL])
  (new certificate-store% (security-level security-level)))

(define certificate-store%
  (class* object% (-certificate-store<%>)
    (init-field [trusted-h '#hash()] ;; Certificate => #t
                [cert-h    '#hash()] ;; Certificate => #t
                [lookups   null]
                [security-level INIT-SECURITY-LEVEL])
    (super-new)

    (define/public (trust? cert)
      (or (hash-ref trusted-h cert #f)
          (for/or ([lu (in-list lookups)]) (send lu trust? cert))))

    (define/public (lookup-by-subject dn)
      (apply append
             (for/list ([cert (in-hash-keys cert-h)]
                        #:when (Name-equal? dn (send cert get-subject)))
               cert)
             (for/list ([lu (in-list lookups)])
               (send lu lookup-by-subject dn))))

    (define/private (copy #:trusted-h [trusted-h trusted-h]
                          #:cert-h [cert-h cert-h]
                          #:lookups [lookups lookups]
                          #:security-level [security-level security-level])
      (new this% (trusted-h trusted-h) (cert-h cert-h)
           (lookups lookups) (security-level security-level)))

    (define/public (add #:untrusted [untrusted-certs null]
                        #:trusted [trusted-certs null])
      (define ((mkcons v) vs) (cons v vs))
      (define cert-h*
        (for*/fold ([h cert-h])
                   ([certs (in-list (list untrusted-certs trusted-certs))]
                    [cert (in-list certs)])
          (hash-set h cert #t)))
      (define trusted-h*
        (for/fold ([h trusted-h])
                  ([cert (in-list trusted-certs)])
          (hash-set h cert #t)))
      (copy #:trusted-h trusted-h* #:cert-h cert-h*))

    (define/public (add-lookups new-lookups)
      (copy #:lookups (append lookups new-lookups)))
    (define/public (set-security-level new-security-level)
      (cond [(eq? security-level new-security-level) this]
            [else (copy #:security-level new-security-level)]))

    (define/public (add-trusted-from-pem-file pem-file)
      (add #:trusted (pem-file->certificates pem-file)))
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
      (define candidates (send store* build-candidate-chains end-cert))
      (unless (or (pair? candidates) empty-ok?)
        (raise-incomplete-chain-error who end-cert))
      (validate-chains candidates valid-time #:empty-ok? empty-ok? #:who who))

    ;; build-candidate-chains : Cert -> (Listof (Listof Cert))
    (define/public (build-candidate-chains end-cert)
      (define (extend chain)
        (define issuer-name (send (car chain) get-issuer))
        (for/list ([issuer-cert (in-list (remove-duplicates (lookup-by-subject issuer-name)))]
                   #:when (not (member issuer-cert chain)))
          (cons issuer-cert chain)))
      (define (loop chains)
        (define-values (complete incomplete)
          (partition (lambda (chain) (trust? (car chain))) chains))
        ;;(eprintf "complete = ~v\n" complete)
        (apply append complete (map (lambda (c) (loop (extend c))) incomplete)))
      (loop (list (list end-cert))))

    ;; validate-chain : (Listof Cert) -> CertificateChain
    (define/public (validate-chain candidate [valid-time (current-seconds)]
                                   #:who [who 'validate-chain])
      (car (validate-chains (list candidate) valid-time #:empty-ok? #f #:who who)))

    ;; validate-chains : (Listof (Listof Cert)) -> (Listof CertificateChain)
    ;; Discards invalid chains, returns certificate-chain% objects for valid.
    (define/public (validate-chains candidates [valid-time (current-seconds)]
                                    #:empty-ok? [empty-ok? #f]
                                    #:who [who 'validate-chains])
      (define cv-chains ;; (Listof CertificateChain)
        (match (filter-results
                #:empty-ok? empty-ok?
                (for/list ([candidate (in-list candidates)])
                  (check-candidate-chain candidate)))
          [(ok cv-chains) cv-chains]
          [(bad (cons errs _))
           (raise-invalid-chain-error who errs)]))
      (define trusted-chains ;; (Listof CertificateChain)
        (match (filter-results
                #:empty-ok? empty-ok?
                (for/list ([chain (in-list cv-chains)])
                  (match (send chain check-trust this valid-time
                               #:security-level security-level)
                    [(ok #t) (ok chain)]
                    [(bad errs) (bad errs)])))
          [(ok chains) chains]
          [(bad (cons errs _))
           (raise-invalid-chain-error who errs)]))
      trusted-chains)

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

    ;; trusted-cache : WeakHasheq[Certificate => #t]
    ;; FIXME: add timeout to cache?
    (define trusted-cache (make-weak-hasheq))

    (define/public (trust? cert)
      (or (hash-ref trusted-cache cert #f)
          (for/or ([trusted (in-list (lookup-by-subject (send cert get-subject)))])
            (equal? trusted cert))))

    (define/public (lookup-by-subject name)
      (define (padto n s) (string-append (make-string (- n (string-length s)) #\0) s))
      (define base (padto 8 (number->string (openssl-Name-hash name) 16)))
      (let loop ([i 0])
        (define file (build-path dir (format "~a.~a" base i)))
        (cond [(file-exists? file)
               (define cert (read-cert-from-file file))
               (cond [(and cert (Name-equal? name (send cert get-subject)))
                      (hash-set! trusted-cache cert #t)
                      (cons cert (loop (add1 i)))]
                     [else (loop (add1 i))])]
              [else null])))

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
