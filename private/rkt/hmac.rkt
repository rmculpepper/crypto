#lang racket/base
(require racket/class
         "../common/interfaces.rkt"
         "../common/common.rkt")
(provide rkt-hmac-impl%)

;; Reference: http://www.ietf.org/rfc/rfc2104.txt

(define rkt-hmac-impl%
  (class* object% (digest-impl<%>)
    (init-field digest)
    (super-new)

    (define/public (get-name) (format "HMAC-~a" (send digest get-name)))
    (define/public (get-size) (send digest get-size))
    (define/public (get-block-size) (send digest get-block-size))
    (define/public (get-hmac-impl who)
      (error who "given HMAC digest implementation"))
    (define/public (hmac-buffer who key buf start end) #f)

    (define/public (new-ctx key)
      (new hmac-ctx% (impl this) (key key) (digest digest)))
    (define/public (generate-hmac-key)
      (send digest generate-hmac-key))
    ))

(define hmac-ctx%
  (class* base-ctx% (digest-ctx<%>)
    (init-field key
                digest
                [ctx #f])
    (inherit-field impl)
    (super-new)

    (define block-size (send digest get-block-size))
    (define ipad (make-bytes block-size #x36))
    (define opad (make-bytes block-size #x5c))
    (let* ([key (cond [(> (bytes-length key) block-size)
                       ;; FIXME: supposed to hash the key
                       (error 'hmac "key too long")]
                      [else key])])
      (define (xor-with-key! pad)
        (for ([i (in-range (bytes-length key))])
          (bytes-set! pad i (bitwise-xor (bytes-ref pad i) (bytes-ref key i)))))
      (xor-with-key! ipad)
      (xor-with-key! opad))

    (unless ctx
      (set! ctx (send digest new-ctx))
      (send ctx update! 'hmac ipad 0 block-size))

    (define/public (update! who buf start end)
      (send ctx update! who buf start end))

    (define/public (final! who buf start end)
      (let* ([mdbuf (make-bytes block-size)]
             [mdlen (send ctx final! who mdbuf 0 block-size)]
             [ctx2 (send digest new-ctx)])
        (send ctx2 update! who opad 0 block-size)
        (send ctx2 update! who mdbuf 0 mdlen)
        (send ctx2 final! who buf start end)))

    (define/public (copy who)
      (new hmac-ctx% (key key) (digest digest) (ctx (send ctx copy))))
    ))
