;; Copyright 2012-2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/class
         racket/match
         "interfaces.rkt"
         "common.rkt"
         "error.rkt")
(provide digest-impl%
         digest-ctx%
         rkt-hmac-ctx%
         config:blake2s
         config:blake2b
         config:cshake)

;; ============================================================
;; Digest

(define digest-impl%
  (class* info-impl-base% (digest-impl<%>)
    (inherit-field info factory)
    (inherit get-spec)
    (super-new)

    (define/override (about) (format "~a digest" (super about)))
    (define/override (to-write-string prefix) (super to-write-string (or prefix "digest:")))

    ;; Info methods
    (define/public (get-size) (send info get-size))
    (define/public (get-size*) (send info get-size*))
    (define/public (get-block-size) (send info get-block-size))
    (define/public (has-config?) (send info has-config?))
    (define/public (get-key-sizes) (send info get-key-sizes))
    (define/public (key-size-ok? keysize) (send info key-size-ok? keysize))
    (define/public (get-config-family) (send info get-config-family))
    (define/public (get-security-strength cr?) (send info get-security-strength cr?))

    (define/public (sanity-check #:size [size #f] #:block-size [block-size #f])
      ;; Use info::get-{block-,}size directly so that subclasses can
      ;; override get-size and get-block-size.
      (when size
        (define info-size (send info get-size))
        (when info-size
          (unless (= size info-size)
            (internal-error "digest size: expected ~s but got ~s\n  digest: ~a"
                            (send info get-size) size (about)))))
      (when block-size
        (unless (= block-size (send info get-block-size))
          (internal-error "block size: expected ~s but got ~s\n  digest: ~a"
                          (send info get-block-size) block-size (about)))))

    ;; new-ctx : Bytes/#f Config -> DigestCtx
    (define/public (new-ctx key config)
      (when key (check-key-size (bytes-length key)))
      (cond [(null? config) (-new-ctx key)]
            [else (-new-ctx2 key config)]))

    ;; -new-ctx : Bytes/#f -> DigestCtx
    (define/public (-new-ctx key)
      (-new-ctx2 key null))

    ;; -new-ctx2 : Bytes/#f Config -> DigestCtx
    (define/public (-new-ctx2 key config)
      (define factory-name (send factory get-name))
      (check-null-config config (get-spec) #:in this)
      (internal-error "unimplemented" #:in this))

    (define/public (check-key-size keysize)
      (unless (key-size-ok? keysize)
        (crypto-error "bad key size\n  given: ~s bytes\n  digest: ~a"
                      keysize (about))))

    (define/public (new-hmac-ctx key)
      (unless (get-size) (err/not-fixed-digest this))
      (-new-hmac-ctx key))

    (define/public (-new-hmac-ctx key)
      (new rkt-hmac-ctx% (impl this) (key key)))

    (define/public (digest src key size config)
      (when (and (not (null? config)) (not (send info has-config?)))
        ;; non-empty config but no config expected; report error
        (check-null-config config (get-spec) #:in #f))
      (define dsize (get-size))
      (or (cond [(or key (not dsize) (and size (not (eqv? size dsize)))) #f]
                [(not (null? config)) #f]
                [else (match src
                        [(? bytes?) (-digest-buffer src 0 (bytes-length src) dsize)]
                        [(bytes-range buf start end) (-digest-buffer buf start end dsize)]
                        [_ #f])])
          (send (new-ctx key config) digest src size)))

    (define/public (hmac key src)
      (or (match src
            [(? bytes?) (-hmac-buffer key src 0 (bytes-length src))]
            [(bytes-range buf start end) (-hmac-buffer key buf start end)]
            [_ #f])
          (send (new-hmac-ctx key) digest src #f)))

    ;; {-digest,-hmac}-buffer : ... -> Bytes/#f
    ;; Return bytes if can compute digest/hmac directly, #f to fall back
    ;; to default ctx code.
    (define/public (-digest-buffer src src-start src-end size) #f)
    (define/public (-hmac-buffer key src src-start src-end) #f)
    ))

(define digest-ctx%
  (class* (state-mixin ctx-base%) (digest-ctx<%>)
    (inherit with-state)
    (inherit-field impl)
    (super-new [state 'open])

    (define/override (to-write-string prefix)
      (super to-write-string (or prefix "digest-ctx:")))

    (define/public (digest src size)
      (update src)
      (final size))

    (define/public (update src)
      (with-state #:ok '(open)
        (lambda ()
          (process-input src (lambda (buf start end) (-update buf start end)))
          (void))))

    (define/public (final size)
      (with-state #:ok '(open) #:post 'closed
        (lambda ()
          (define dsize (send impl get-size))
          (cond [dsize
                 (when (and size (not (= size dsize)))
                   (crypto-error (string-append
                                  "wrong size given for non-XOF digest"
                                  "\n  given: ~e\n  expected: ~s")
                                 size dsize #:in this))
                 (define dest (make-bytes dsize))
                 (-final! dest)
                 dest]
                [else
                 (unless size
                   (crypto-error "no output size given for XOF" #:in this))
                 (define dest (make-bytes size))
                 (-final-xof! dest)
                 dest]))))

    (define/public (copy)
      (with-state #:ok '(open) (lambda () (-copy))))

    (abstract -update) ;; Bytes Nat Nat -> Void
    (abstract -final!) ;; Bytes -> Void
    (define/public (-final-xof! buf) (-final! buf))
    (define/public (-copy) #f) ;; -> digest-ctx<%> or #f
    ))

;; ============================================================
;; HMAC

;; Reference: http://www.ietf.org/rfc/rfc2104.txt

(define rkt-hmac-ctx%
  (class digest-ctx%
    (init-field key [ctx #f])
    (inherit-field impl)
    (super-new)

    (define/override (to-write-string prefix)
      (send impl to-write-string (or prefix "hmac-ctx:")))

    (define block-size (send impl get-block-size))
    (define ipad (make-bytes block-size #x36))
    (define opad (make-bytes block-size #x5c))
    (when (> (bytes-length key) block-size)
      (set! key (send impl digest key #f #f)))
    (define (xor-with-key! pad)
      (for ([i (in-range (bytes-length key))])
        (bytes-set! pad i (bitwise-xor (bytes-ref pad i) (bytes-ref key i)))))
    (xor-with-key! ipad)
    (xor-with-key! opad)

    (unless ctx
      (set! ctx (send impl new-ctx #f null))
      (send ctx update ipad))

    (define/override (-update buf start end)
      (if (and (= start 0) (= end (bytes-length buf)))
          (send ctx update buf)
          (send ctx update (bytes-range buf start end))))

    (define/override (-final! buf)
      (define mdbuf (send ctx final #f))
      (define ctx2 (send impl new-ctx #f null))
      (send ctx2 update (list opad mdbuf))
      (bytes-copy! buf 0 (send ctx2 final #f)))

    (define/override (-copy)
      (let ([ctx (send ctx copy)])
        (and ctx (new this% (impl impl) (key key) (ctx ctx)))))
    ))

;; ------------------------------------------------------------

(define config:blake2s
  (let ([ok-bytes? (lambda (v) (and (bytes? v) (<= (bytes-length v) 8)))]
        [desc "bytes with length <= 8"])
    `((salt   ,ok-bytes? ,desc #:opt #"")
      (custom ,ok-bytes? ,desc #:opt #""))))

(define config:blake2b
  (let ([ok-bytes? (lambda (v) (and (bytes? v) (<= (bytes-length v) 16)))]
        [desc "bytes with length <= 16"])
    `((salt   ,ok-bytes? ,desc #:opt #"")
      (custom ,ok-bytes? ,desc #:opt #""))))

(define config:cshake
  `((function ,bytes? #f #:opt #"")
    (custom   ,bytes? #f #:opt #"")))
