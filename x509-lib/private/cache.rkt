#lang racket/base
(require racket/match
         racket/class
         "interfaces.rkt")
(provide (all-defined-out)
         no-cache)

(define db-cache%
  (class* object% (cache<%>)
    (init-field parent)
    (super-new)

    (define/public (make-certificate der go)
      (send parent make-certificate der go))

    (define/public (fetch-ocsp ocsp-url req go)
      ;; FIXME: check db for entry; otherwise:
      (define r (send parent fetch-ocsp ocsp-url req go))
      ;; FIXME: add r to db
      r)

    (define/public (fetch-crl crl-url go)
      ;; FIXME: check db for entry; otherwise:
      (define r (send parent fetch-crl crl-url go))
      ;; FIXME: add r to db
      r)

    (define/public (trim oldest-time)
      ;; FIXME: delete records older than oldest-time
      (void))
    ))

(define mem-cache%
  (class* object% (cache<%>)
    (init-field parent)
    (super-new)

    (define/private (get! cache-h key fault)
      (define r (hash-ref cache-h key #f))
      (define now (current-seconds))
      (if (and r (< now (send r get-expiration-time)))
          r
          (let ([r (fault)])
            (eprintf "fault for ~e\n" key)
            (when (cachable? r) (hash-set! cache-h key r))
            r)))

    ;; cert-h : Hash[Bytes => Certificate]
    (define cert-h (make-weak-hash))

    (define/public (make-certificate der go)
      (hash-ref! cert-h der (lambda () (send parent make-certificate der go))))

    ;; ocsp-h : Hash[(cons String[URL] Bytes[Req-DER]) => ocsp-response%]
    (define ocsp-h (make-hash))

    (define/public (fetch-ocsp ocsp-url req go)
      (get! ocsp-h (cons ocsp-url req)
            (lambda () (send parent fetch-ocsp ocsp-url req go))))

    ;; crl-h : Hash[String[URL] => crl%]
    (define crl-h (make-hash))

    (define/public (fetch-crl crl-url go)
      (get! crl-h crl-url
            (lambda () (send parent fetch-crl crl-url go))))

    (define/public (trim oldest-time)
      (void))
    ))
