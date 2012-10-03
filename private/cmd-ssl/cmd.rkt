#lang racket/base
(require racket/class
         racket/system
         racket/string
         racket/port
         "../common/interfaces.rkt"
         "../common/common.rkt"
         (only-in "../ssl/util.rkt" unhex))
(provide (all-defined-out))

;; ============================================================

(define process-handler%
  (class base-ctx%
    (super-new)

    (field [sp #f]
           [spout #f]
           [spin #f]
           [sperr #f])

    (set!-values (sp spout spin sperr)
      (apply subprocess #f #f #f "/usr/bin/openssl" (get-openssl-args)))

    (abstract get-openssl-args)

    (define/public (write! who buf start end)
      (write-bytes buf spin start end)
      (flush-output spin)
      (void))

    (define/public (close/read who)
      (close-output-port spin)
      (sync sp)
      (close-input-port sperr)
      (begin0 (port->bytes spout)
        (close-input-port spout)))
    ))

;; ============================================================

(define digest-impl%
  (class* object% (digest-impl<%>)
    (init-field name
                size)
    (super-new)

    (define/public (get-name) name)
    (define/public (get-size) size)

    (define/public (new-ctx)
      (new digest-ctx% (impl this)))

    (define/public (get-hmac-impl who)
      (error who "not implemented"))
    (define/public (hmac-buffer who key buf start end) #f)
    (define/public (generate-hmac-key)
      (let ([key (make-bytes size)])
        (for ([i (in-range size)])
          (bytes-set! key i (random 255)))
        key))
    ))

(define digest-ctx%
  (class* process-handler% (digest-ctx<%>)
    (inherit-field impl)
    (inherit write! close/read)
    (super-new)

    (define/override (get-openssl-args)
      (list "dgst" (format "-~a" (send impl get-name))))

    (define/public (update! who buf start end)
      (write! who buf start end))

    (define/public (final! who buf start end)
      (let* ([output (close/read who)]
             [hex-md (string-trim (bytes->string/latin-1 output))]
             [md (unhex (string->bytes/latin-1 hex-md))])
        (bytes-copy! buf start md)
        (bytes-length md)))

    (define/public (copy who)
      (error who "not implemented"))
    ))

(define (di name size) (new digest-impl% (name name) (size size)))

(define digest:md5 (di "md5" 16))
(define digest:sha1 (di "sha1" 20))

;; ============================================================

