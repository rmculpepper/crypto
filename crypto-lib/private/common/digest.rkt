;; Copyright 2012-2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         scramble/bundle
         scramble/struct
         "interfaces.rkt"
         "common.rkt"
         "error.rkt")

#;
(provide digest-impl%
         digest-ctx%
         rkt-hmac-ctx%
         config:blake2s
         config:blake2b
         config:blake2s+size
         config:blake2b+size
         config:cshake)

;; ============================================================
;; Digest

(define-interface digest-impl-common$
  ([sanity-check (->* [] [#:size (or/c nat? #f) #:block-size (or/c nat? #f)] void?)]
   [digest-buffer (-> any/c bytes? nat? nat? nat? (or/c bytes? #f))]
   [new-ctx1 (-> any/c (or/c bytes? #f) intctx/c)]
   [new-ctx2 (-> any/c (or/c bytes? #f) config/c intctx/c)])
  #:generic $$)

(struct digest-impl info-impl-base ()
  #:properties
  (method-properties
   #:export ([digest-impl$ #:prefix %]
             [simple-write$ #:prefix %]
             [digest-impl-common #:prefix %%])
   #:import ([simple-write$ #:super #:prefix super-])
   (define-struct-abbrevs digest-impl)
   (define (%to-write-prefixes self)
     (list "impl" "digest" (super-to-write-prefixes self)))

   ;; ---- digest-info

   ;; use fallbacks for di-size, di-config-family, di-key-size-ok?
   (define (%di-size* self) ($di-size* (.info self)))
   (define (%di-block-size self) ($di-block-size (.info self)))
   (define (%di-has-config? self) ($di-has-config? (.info self)))
   (define (%di-key-sizes self) ($di-key-sizes (.info self)))
   (define (%di-security-strength self cr?)
     ($di-security-strength (.info self) cr?))

   ;; ---- digest-impl

   (define (%%sanity-check #:size [size #f] #:block-size [block-size #f])
     ;; Use info's size and block-size directly so that subclasses can override
     ;; $di-size, $di-block-size.
     (when size
       (define info-size ($di-size (.info self)))
       (when info-size
         (unless (= size info-size)
           (internal-error "digest size: expected ~s but got ~s"
                           info-size size #:in self))))
     (when block-size
       (define info-block-size ($di-block-size (.info self)))
       (unless (= block-size info-block-size)
         (internal-error "block size: expected ~s but got ~s"
                         info-block-size block-size #:in self))))

    (define (%di-new-ctx self key config)
      (cond [(null? config) ($$new-ctx1 self key)]
            [else ($$new-ctx2 self key config)]))

    (define (%%new-ctx1 self key)
      ($$new-ctx2 self key null))

    (define (%%new-ctx2 self key config)
      (check-null-config config (get-spec) #:in this)
      (internal-error "unimplemented" #:in self))

    ;; abstract: di-update, di-final, di-copy
    ))


(define (digest*-digest impl src key size config)
  (define (move-size-early config size)
    (cond [(and size (not (assq 'size config)))
           (values (cons `(size ,size) config) #f)]
          [else (values config size)]))
  (define (digest-src impl src key dsize)
    (match src
      [(? bytes?)
       ($$digest-buffer self src 0 (bytes-length src) dsize)]
      [(bytes-range buf start end)
       ($$digest-buffer self buf start end dsize)]
      [_ #f]))
  (define (fallback)
    (digest*-digest-fallback self src key size config))
  (define dsize ($di-size* self))
  (cond [(exact-nonnegative-integer? dsize)
         (cond [(and (eq? key #f)
                     (or (eq? size #f) (eqv? size dsize))
                     (null? config))
                (or (digest-src self src key dsize) (fallback))]
               [else (fallback)])]
        [(eq? dsize 'va)
         (let-values ([(config size) (move-size-early config size)])
           (digest*-digest-fallback self src key size config))]
        [else (fallback)]))

(define (digest*-digest-fallback impl src key size config)
  (define-values (ictx dsize) (digest*-new-ctx impl key config))
  (digest*-update impl ictx src)
  (digest*-final impl ictx dsize size))

(define (digest*-new-ctx impl key config)
  (define (check-key-size keysize)
    (unless ($di-key-size-ok? impl keysize)
      (crypto-error "bad key size\n  given: ~s bytes"
                    keysize #:in impl)))
  (when key (check-key-size (bytes-length key)))
  ($di-new-ctx impl key config))

(define (digest*-update impl ictx src)
  (process-input src
                 (lambda (buf start end)
                   ($di-update impl ictx buf start end))))

(define (digest*-final impl ictx dsize size)
  (define dest
    (cond [dsize
           (when (and size (not (= size dsize)))
             (crypto-error (string-append
                            "wrong size given for non-XOF digest"
                            "\n  given: ~e\n  expected: ~s")
                           size dsize #:in this))
           (make-bytes dsize)]
          [else
           (unless size
             (crypto-error (string-append
                            "no output size given for "
                            "late variable-size digest")
                           #:in this))
           (make-bytes size)]))
  ($di-final impl ictx dest)
  dest)))

;; ----

(struct digest-ctx state-ctx (osize))

(define (digest-new-ctx impl key config)
  (define-values (ictx dsize) ($di-new-ctx impl key config))
  (digest-ctx impl ictx 'open (make-semaphore 1) dsize))

(define (digest-ctx-update dctx src)
  ($call-with-state
   dctx #:ok '(open) #:post 'closed
   (lambda ()
     (match (ctx impl ictx) dctx)
     (digest*-update impl ictx src))))

(define (digest-ctx-final dctx size)
  ($call-with-state
   dctx #:ok '(open) #:post 'closed
   (lambda ()
     (match (digest-ctx impl ictx _ _ dsize) dctx)
     (digest*-final impl ictx dsize size))))

(define (digest-ctx-copy dctx)
  ($call-with-state
   dctx #:ok '(open)
   (lambda ()
     (match (digest-ctx impl ictx _ state dsize) dctx)
     (define ictx2 ($di-copy impl ictx))
     (and ictx2 (digest-ctx impl ictx2 state (make-semaphore 1) dsize)))))



(define digest-ctx%
  (class* state-ctx% (digest-ctx<%>)
    (inherit with-state)
    (inherit-field impl)
    (init-field [digest-size #f]) ;; Nat/#f, #f means XOF (once initialized)
    (super-new [state 'open])

    ;; var-sized digests (eg, blake2b) should set digest-size based on config
    ;; fixed-size digests and XOFs get size from impl
    (unless digest-size (set! digest-size (send impl get-size)))

    (define/override (to-write-string prefix)
      (super to-write-string (or prefix "digest-ctx:")))

    (define/private (clone inits)
      (dynamic-instantiate this% null (map (lambda (l) (cons (car l) (cadr l))) inits)))

    (abstract -update) ;; Bytes Nat Nat -> Void
    (abstract -final!) ;; Bytes -> Void
    (define/public (-final-xof! buf) (-final! buf))
    (define/public (-copy-inits) #f) ;; -> (Listof (list Symbol Any)) or #f
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

    (define/override (-copy-inits)
      (let ([ctx (send ctx copy)])
        (and ctx `((key ,key) (ctx ,ctx)))))
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

(define config:blake2s+size
  (let ([ok-size? (lambda (v) (and (exact-integer? v) (<= 0 v 32)))]
        [desc "integer between 0 and 32"])
    `((size ,ok-size? ,desc #:req) ,@config:blake2s)))

(define config:blake2b+size
  (let ([ok-size? (lambda (v) (and (exact-integer? v) (<= 0 v 64)))]
        [desc "integer between 0 and 64"])
    `((size ,ok-size? ,desc #:req) ,@config:blake2b)))

(define config:cshake
  `((function ,bytes? #f #:opt #"")
    (custom   ,bytes? #f #:opt #"")))
