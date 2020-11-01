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
         "asn1.rkt"
         "stringprep.rkt"
         "cert-data.rkt"
         "cert.rkt"
         (only-in crypto/private/common/asn1 relation-ref))
(provide (all-defined-out))

;; References:
;; - RFC 5280 (https://tools.ietf.org/html/rfc5280)
;; - RFC 6818 (general updates) (https://tools.ietf.org/html/rfc6818)
;; - RFC 8398 and 8399 (Internationalization) (https://tools.ietf.org/html/rfc8398,
;;   https://tools.ietf.org/html/rfc8399)

;; FIXME: asn1 parser returns mutable bytes,strings?

;; FIXME: need mechanism for disallowing obsolete algorithms (eg, 1024-bit RSA / DSA)

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

;; A CandidateChain is (list TrustAnchor Cert ...),
;; where TrustAnchor is currently always also a Cert.

;; check-candidate-chain : CandidateChain -> (values CertificateChain/#f ErrorList)
;; Checks the properties listed under certificate-chain%. Also checks that the
;; chain's validity period includes the given valid-time argument.
(define (check-candidate-chain certs valid-time)
  (when (null? certs) (error 'get-chain-errors "empty candidate chain"))
  (define N (sub1 (length certs))) ;; don't count trust anchor
  (define vi (new validation% (N N)))
  (send (car certs) check-valid-period 0 vi valid-time valid-time)
  (for ([issuer (in-list certs)]
        [cert (in-list (cdr certs))]
        [index (in-naturals 1)])
    (send cert check-valid-period index vi valid-time valid-time)
    (send cert check-link-in-chain index issuer vi (= index N)))
  (define ok-start (send vi get-from-time))
  (define ok-end (send vi get-to-time))
  (define errs (send vi get-errors))
  (cond [(null? errs)
         (define chain
           (new certificate-chain% (chain certs)
                (ok-start ok-start) (ok-end ok-end)))
         (values chain null)]
        [else
         (values #f errs)]))

;; validation% represents (mutable) state during chain validation
(define validation%
  (class object%
    (init N)
    (init-field [max-path-length N]
                [from-time #f]
                [to-time #f]
                [name-constraints null]
                [explicit-policy (add1 N)]
                [policy-mapping (add1 N)]
                [inhibit-anypolicy (add1 N)]
                [errors null]) ;; ErrorList, mutated
    (super-new)

    (define/public (decrement-counters) ;; 6.1.4 (b)
      (cond [(positive? max-path-length)
             (set! max-path-length (sub1 max-path-length))]
            [else (add-error 'max-path-length)])
      (unless (zero? explicit-policy) (set! explicit-policy (sub1 explicit-policy)))
      (unless (zero? policy-mapping) (set! policy-mapping (sub1 policy-mapping)))
      (unless (zero? inhibit-anypolicy) (set! inhibit-anypolicy (sub1 inhibit-anypolicy))))

    (define/public (intersect-valid-period from to)
      (set! from-time (if from-time (max from from-time) from))
      (set! to-time (if to-time (min to to-time) to)))

    (define/public (get-from-time) from-time)
    (define/public (get-to-time) to-time)

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

;; A CertificateChain is an instance of certificate-chain%, containing a
;; non-empty list of certs of the form (list trust-anchor ... end-cert).

;; A certificate chain is "chain-valid" if it satisfies all of the following:
;; - each cert issued the next, and signatures are valid
;; - the intersection of each cert's validity period is not empty
;;   (the intersection of the validity periods is stored)
;; - name constraints, path length constraints, etc are checked
;; Beware the following limitations of "chain-validity":
;; - It DOES NOT check that the trust anchor is actually trusted.
;; - It DOES NOT check that the end-certificate is suitable for any particular purpose.

;; A certificate chain is "trusted" given a x509-store and a time interval if it
;; satisfies all of the following:
;; - it is "chain-valid"
;; - the chain's validity period includes the given time interval
;; - the chain's trust anchor is trusted by the given x509-store

;; A certificate chain is "valid for a purpose" if
;; - the chain is "trusted", and
;; - the chain's end-certificate is suitable for the given purpose

;; A certificate is "suitable for a purpose of identifying a TLS server" if
;; - the cert's subjectAlternativeName contains a dNSName pattern that matches
;;   the TLS server's fully-qualified host name
;; - OPTIONAL: ... sufficient security level of algorithms ...
;; - OPTIONAL: ... validity period < some limit (825 days) ...
;; - If KeyUsage is present, must contain at least one of
;;     digitalSignature, keyEncipherment, keyAgreement.
;;   (IIUC (??), cannot be more precise w/o knowing TLS ciphersuite negotiated.)
;; - If ExtendedKeyUsage is present, then it must contain id-kp-serverAuth.
;; - References:
;;   - https://tools.ietf.org/html/rfc5246#section-7.4.2
;;   - https://tools.ietf.org/html/rfc5280#section-4.2.1.12

(define certificate-chain%
  (class* object% (certificate-chain<%>)
    ;; chain : (list trust-anchor<%> certificate% ...+)
    ;; Note: In 6.1, trust anchor is not considered part of chain.
    (init-field chain ok-start ok-end)
    (super-new)

    (define/public (custom-write out mode)
      (fprintf out "#<certificate-chain: ~a>"
               (Name->string (send (get-end-certificate) get-subject))))

    (define N (length (cdr chain))) ;; don't count trust anchor

    (define/public (get-chain) chain)
    (define/public (get-end-certificate) (last chain))
    (define/public (get-trust-anchor) (first chain))

    (define/public (trusted? store [from-time (current-seconds)] [to-time from-time])
      (null? (check-trust store from-time to-time)))

    ;; check-trust : Store Seconds Seconds -> ErrorList
    (define/public (check-trust store [from-time (current-seconds)] [to-time from-time])
      (append (cond [(send store trust? (get-trust-anchor)) '()]
                    [else '((0 . trust-anchor:not-trusted))])
              (cond [(<= ok-start from-time to-time ok-end) '()]
                    [else
                     (let ([vi (new validation% (N (sub1 (length chain)))
                                    (from-time from-time) (to-time to-time))])
                       (for ([cert (in-list chain)] [index (in-naturals 1)])
                         (send cert check-valid-period index vi from-time to-time)))])))
    ))

;; ============================================================

;; read-pem-certs : InputPort -> (Listof Bytes)
(define (read-pem-certs in)
  (for/list ([v (in-port (lambda (in) (read-pem in #:only '(#"CERTIFICATE"))) in)])
    (cdr v)))

;; read-certs : Path -> (Listof certificate%)
(define (read-certs file)
  (define ders (call-with-input-file file read-pem-certs))
  (map (lambda (der) (new certificate% (der der))) ders))

;; ============================================================

(define x509-store%
  (class* object% (x509-store<%>)
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
      (add #:trusted-certs (read-certs pem-file)))
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

(define empty-x509-store (new x509-store%))

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
      (match (call-with-input-file* file read-pem-certs)
        [(list der) (new certificate% (der der))]
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
