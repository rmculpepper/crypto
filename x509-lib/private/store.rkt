#lang racket/base
(require racket/class
         racket/match
         crypto/pem
         asn1
         "interfaces.rkt"
         "x509-asn1.rkt"
         "x509-info.rkt"
         "x509.rkt")
(provide (all-defined-out))

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
    ))

;; ============================================================

(define x509-openssl-directory-store%
  (class* object% (x509-store<%>)
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

    (define/public (add #:untrusted-certs [untrusted-certs null]
                        #:trusted-certs [trusted-certs null]
                        #:stores [new-stores null])
      (define store (new x509-store% (stores (list this))))
      (send store add
            #:untrusted-certs untrusted-certs
            #:trusted-certs trusted-certs
            #:stores new-stores))
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

;; ============================================================

(define root (new x509-openssl-directory-store% (dir "/etc/ssl/certs")))
(define current-x509-store (make-parameter (new x509-store% (stores (list root)))))
