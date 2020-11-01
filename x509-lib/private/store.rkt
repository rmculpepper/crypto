#lang racket/base
(require racket/match
         racket/class
         racket/list
         asn1
         crypto/pem
         "interfaces.rkt"
         "asn1.rkt"
         "cert-data.rkt"
         "cert.rkt"
         "chain.rkt")
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

(define (empty-certificate-store) (new certificate-store%))

(define certificate-store%
  (class* object% (certificate-store<%>)
    (init-field [trusted-h '#hash()]
                [cert-h    '#hash()]
                [stores null])
    (super-new)

    (define/public (trust? cert)
      (or (hash-ref trusted-h (send cert get-der) #f)
          (for/or ([store (in-list stores)]) (send store trust? cert))))

    (define/public (lookup-by-subject dn)
      (apply append
             (for/list ([cert (in-hash-keys cert-h)]
                        #:when (Name-equal? dn (send cert get-subject)))
               cert)
             (for/list ([store (in-list stores)]) (send store lookup-by-subject dn))))

    (define/public (add #:untrusted-certs [untrusted-certs null]
                        #:trusted-certs [trusted-certs null]
                        #:stores [new-stores null])
      (define ((mkcons v) vs) (cons v vs))
      (define cert-h*
        (for*/fold ([h cert-h])
                   ([certs (in-list (list untrusted-certs trusted-certs))]
                    [cert (in-list certs)])
          (hash-set h cert #t)))
      (define trusted-h*
        (for/fold ([h trusted-h])
                  ([cert (in-list trusted-certs)])
          (hash-set h (send cert get-der) #t)))
      (new this% (trusted-h trusted-h*) (cert-h cert-h*)
           (stores (append stores new-stores))))

    (define/public (add-trusted-from-pem-file pem-file)
      (add #:trusted-certs (pem-file->certificates pem-file)))
    (define/public (add-trusted-from-openssl-directory dir)
      (add #:stores (list (new x509-lookup:openssl-trusted-directory% (dir dir)))))

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
      (define store* (add #:untrusted-certs other-untrusted-certs))
      (define candidates (send store* build-candidate-chains end-cert))
      (unless (or (pair? candidates) empty-ok?)
        (raise-incomplete-chain-error who end-cert))
      (check-chains candidates valid-time #:empty-ok? empty-ok? #:who who))

    ;; build-candidate-chains : Cert -> (Listof (Listof Cert))
    (define/public (build-candidate-chains end-cert)
      (define (loop chains)
        (cond [(pair? chains)
               (define chains* (append* (map loop1 chains)))
               (define-values (complete incomplete)
                 (partition (lambda (chain) (trust? (car chain))) chains*))
               (append complete (loop incomplete))]
              [else null]))
      (define (loop1 chain)
        (define issuer-name (send (car chain) get-issuer))
        (for/list ([issuer-cert (in-list (remove-duplicates (lookup-by-subject issuer-name)))]
                   #:when (not (member issuer-cert chain)))
          (cons issuer-cert chain)))
      (loop (list (list end-cert))))

    ;; check-chain : (Listof Cert) -> CertificateChain
    (define/public (check-chain candidate [valid-time (current-seconds)]
                                #:who [who 'check-chain])
      (car (check-chains (list candidate) valid-time #:empty-ok? #f #:who who)))

    ;; check-chains : (Listof (Listof Cert)) -> (Listof CertificateChain)
    ;; Discards invalid chains, returns certificate-chain% objects for valid.
    (define/public (check-chains candidates [valid-time (current-seconds)]
                                 #:empty-ok? [empty-ok? #f]
                                 #:who [who 'check-chains])
      (define cv-chains
        (fault-filter candidates empty-ok?
                      (lambda (candidate)
                        (check-candidate-chain candidate valid-time))
                      (lambda (candidate errs)
                        (raise-invalid-chain-error who candidate errs))))
      (define trusted-chains
        (fault-filter cv-chains empty-ok?
                      (lambda (chain)
                        (define errs (send chain check-trust this valid-time))
                        (if (null? errs) (values chain null) (values #f errs)))
                      (lambda (chain errs)
                        (raise-invalid-chain-error who chain errs))))
      trusted-chains)
    ))

(define (raise-invalid-chain-error who end-cert errs)
  (let/ec escape
    (define msg (format "~s: chain validation failed\n  errors: ~e" who errs))
    (raise (exn:x509:chain msg (continuation-marks escape) errs))))
(define (raise-incomplete-chain-error who end-cert)
  (let/ec escape
    (define msg (format "~s: failed to build complete chain\n  end certificate: ~e" who end-cert))
    (raise (exn:x509:chain msg (continuation-marks escape) '(incomplete)))))

;; fault-filter : (Listof X) Bool (X -> (values Y/#f List)) (X List -> Z)
;;             -> (Listof Y) or Z
(define (fault-filter xs empty-ok? get-y/errs handle-errs)
  (define-values (ok-ys errss)
    (for/lists (ys errss #:result (values (filter values ys) errss))
               ([x (in-list xs)])
      (get-y/errs x)))
  (cond [(or (pair? ok-ys) empty-ok?) ok-ys]
        [(pair? errss) (handle-errs (car xs) (car errss))]
        [else (error 'fault-filter "internal error: given empty list")]))

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
            (send trusted equal-to cert))))

    (define/public (lookup-by-subject dn)
      (define (padto n s) (string-append (make-string (- n (string-length s)) #\0) s))
      (define base (padto 8 (number->string (dn-hash (asn1->bytes Name dn)) 16)))
      (let loop ([i 0])
        (define file (build-path dir (format "~a.~a" base i)))
        (cond [(file-exists? file)
               (define cert (read-cert-from-file file))
               (cond [(and cert (Name-equal? dn (send cert get-subject)))
                      (hash-set! trusted-cache cert #t)
                      (cons cert (loop (add1 i)))]
                     [else (loop (add1 i))])]
              [else null])))

    (define/private (dn-hash dn-der)
      (local-require (submod "." openssl-x509))
      (NAME-hash dn-der))

    ;; FIXME: cache reads?

    (define/private (read-cert-from-file file)
      (match (pem-file->certificates file)
        [(list cert) cert]
        [_ (begin0 #f (log-x509-error "bad certificate PEM file: ~e" file))]))
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
  (define-ssl d2i_X509_NAME
    (_fun (_pointer = #f) (_ptr i _pointer) _long -> _X509_NAME/null)
    #:wrap (allocator X509_NAME_free))
  (define-ssl X509_NAME_hash (_fun _X509_NAME -> _long))
  (define (NAME-hash dn-der)
    (define dn (d2i_X509_NAME dn-der (bytes-length dn-der)))
    (begin0 (X509_NAME_hash dn) (X509_NAME_free dn))))
