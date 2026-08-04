;; Copyright 2012-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         racket/contract/base
         scramble/bundle
         scramble/struct
         "catalog.rkt"
         "interfaces.rkt"
         "common.rkt"
         "error.rkt")
(provide (struct-out common-digest-impl)
         (interface-out digest-inner-impl$)
         (struct-out rkt-hmac-inner-impl)
         config:blake2s
         config:blake2b
         config:blake2s+size
         config:blake2b+size
         config:cshake)

;; ============================================================
;; Digest

(struct common-digest-ctx digest-ctx
  (csize    ;; (U Nat #f) -- default/configured size; #f only if late-size ('vz)
   ))

(struct common-digest-impl info-impl-base
  (inner    ;; DigestInnerImpl
   )
  #:properties
  (method-properties
   #:export ([digest-impl$ #:prefix %]
             [simple-write$ #:prefix %])
   #:import ([simple-write$ #:super #:prefix super-])
   (define-struct-abbrevs common-digest-impl)
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

   (define (%digest self src key size config)
     (define (fallback size config)
       (digest* self src key size config))
     (define dsize ($di-size* self))
     (cond [(exact-nonnegative-integer? dsize)
            (cond [(and (eq? key #f)
                        (or (eq? size #f) (eqv? size dsize))
                        (null? config))
                   (or (match src
                         [(? bytes?)
                          ($dii-digest-buffer (.inner self) src 0 (bytes-length src) dsize)]
                         [(bytes-range buf start end)
                          ($dii-digest-buffer (.inner self) buf start end dsize)]
                         [_ #f])
                       (fallback size config))]
                  [else (fallback size config)])]
           [(eq? dsize 'va)
            (define-values (size* config*)
              (cond [(and size (not (assq 'size config)))
                     (values #f (cons `(size ,size) config))]
                    [else (values size config)]))
            (fallback size* config*)]
           [else (fallback size config)]))

   (define (digest* self src key size config)
     (define dctx ($di-new-ctx self key config))
     (di-update* self dctx src)
     (di-final* self dctx size))

   (define (%di-new-ctx self key config)
     (when key
       (define keysize (bytes-length key))
       (unless ($di-key-size-ok? self keysize)
         (crypto-error "bad key size\n  given: ~s bytes"
                       keysize #:in self)))
     (define lock (make-statelock 'open))
     (cond [(null? config)
            (define ic ($dii-new-ctx1 (.inner self) self key))
            (common-digest-ctx self ic lock ($di-size self))]
           [else
            (define-values (ic csize)
              ($dii-new-ctx2 (.inner self) self key config))
            (common-digest-ctx self ic lock csize)]))

   (define (%di-update self dctx src)
     (call-with-state
      dctx #:ok '(open)
      (lambda (s) (di-update* self dctx src))))

   (define (di-update* self dctx src)
     (define ic (ctx-inner dctx))
     (define iimpl (.inner self))
     (process-input src
                    (lambda (buf start end)
                      ($dii-update iimpl ic buf start end)
                      (void))))

   (define (%di-final self dctx size)
     (call-with-state
      dctx #:ok '(open) #:post 'closed
      (lambda (s) (di-final* self dctx size))))

   (define (di-final* self dctx size)
     (match-define (common-digest-ctx _ ic _ csize) dctx)
     (define outsize
       (cond [csize
              (when (and size (not (= size csize)))
                (crypto-error (string-append
                               "wrong size given for non-XOF digest"
                               "\n  given: ~e\n  expected: ~s")
                              size csize #:in self))
              csize]
             [else
              (unless size
                (crypto-error (string-append
                               "no output size given for "
                               "late variable-size digest")
                              #:in self))
              size]))
     ($dii-final (.inner self) ic outsize))

   (define (%di-copy self dctx)
     (call-with-state
      dctx #:ok '(open)
      (lambda (s) (di-copy* self dctx))))

   (define (di-copy* self dctx)
     (match-define (common-digest-ctx impl ic lock csize) dctx)
     (define ic2 ($dii-copy (.inner self) ic))
     (and ic2 (common-digest-ctx impl ic2 (copy-statelock lock) csize)))))

(define (digest-sanity-check impl #:size [size #f] #:block-size [block-size #f])
  ;; Use info's size and block-size directly so that subclasses can override
  ;; $di-size, $di-block-size.
  (when size
    (define info-size ($di-size ($get-info impl)))
    (when info-size
      (unless (= size info-size)
        (internal-error "digest size: expected ~s but got ~s"
                        info-size size #:in impl))))
  (when block-size
    (define info-block-size ($di-block-size ($get-info impl)))
    (unless (= block-size info-block-size)
      (internal-error "block size: expected ~s but got ~s"
                      info-block-size block-size #:in impl))))

;; ------------------------------------------------------------

(define-interface digest-inner-impl$
  ([dii-digest-buffer
    (-> digest-inner-impl$? bytes? nat? nat? nat?
        (or/c bytes? #f))]
   [dii-new-ctx1
    (-> digest-inner-impl$? digest-impl? (or/c bytes? #f)
        ictx/c)]
   [dii-new-ctx2
    (-> digest-inner-impl$? digest-impl? (or/c bytes? #f) config/c
        (values ictx/c (or/c nat? #f)))]
   [dii-update
    (-> digest-inner-impl$? ictx/c bytes? nat? nat?
        any)]
   [dii-final
    (-> digest-inner-impl$? ictx/c nat?
        bytes?)]
   [dii-copy
    (-> digest-inner-impl$? ictx/c
        (or/c ictx/c #f))])
  #:fallbacks
  (let ()
    (define (dii-digest-buffer self buf start end) #f)
    (define (dii-new-ctx1 self di key) ($dii-new-ctx2 self di key null))
    (define (dii-new-ctx2 self di key config)
      (unless (null? config) (check-config config null #:in di))
      (internal-error "unimplemented" #:in di))
    (hasheq 'dii-digest-buffer dii-digest-buffer
            'dii-new-ctx1 dii-new-ctx1
            'dii-new-ctx2 dii-new-ctx2))
  #:generics-prefix $)

;; ============================================================
;; HMAC

;; Reference: http://www.ietf.org/rfc/rfc2104.txt

(struct rkt-hmac-ictx
  ([ipad #:mutable] ;; Bytes or #f -- #f after update (used for copy)
   opad             ;; Bytes
   dctx             ;; DigestCtx
   ))

(struct rkt-hmac-inner-impl
  (di   ;; DigestImpl
   )
  #:properties
  (method-properties
   #:export ([digest-inner-impl$ #:prefix %])
   (define-struct-abbrevs rkt-hmac-inner-impl)

   (define (%dii-new-ctx1 self di key)
     (define block-size ($di-block-size (.di self)))
     (define ipad (make-bytes block-size #x36))
     (define opad (make-bytes block-size #x5c))
     (when (> (bytes-length key) block-size)
       (set! key ($digest (.di self) key #f #f null)))
     (define (xor-with-key! pad)
       (for ([i (in-range (bytes-length key))])
         (bytes-set! pad i (bitwise-xor (bytes-ref pad i) (bytes-ref key i)))))
     (xor-with-key! ipad)
     (xor-with-key! opad)
     (new-ctx* self ipad opad))

   (define (new-ctx* self ipad opad)
     (define block-size ($di-block-size (.di self)))
     (define dctx ($di-new-ctx (.di self) #f null))
     ($di-update (.di self) dctx ipad 0 block-size)
     (rkt-hmac-ictx ipad opad dctx))

   (define (%dii-update self ic buf start end)
     (match-define (rkt-hmac-ictx ipad _ dctx) ic)
     (when ipad (set-rkt-hmac-ictx-ipad! ic #f))
     (if (and (= start 0) (= end (bytes-length buf)))
         ($di-update (.di self) dctx buf)
         ($di-update (.di self) dctx (bytes-range buf start end))))

   (define (%dii-final self ic size)
     (match-define (rkt-hmac-ictx _ opad dctx) ic)
     (define mdbuf ($di-final (.di self) dctx #f))
     (define dctx2 ($di-new-ctx (.di self) #f null))
     ($di-update (.di self) dctx2 (list opad mdbuf))
     ($di-final (.di self) size))

   (define (%dii-copy self ic)
     (match-define (rkt-hmac-ictx ipad opad dctx) ic)
     (cond [ipad (new-ctx* self ipad opad)]
           [else (let ([dctx2 ($di-copy (.di self) dctx)])
                   (and dctx2 (rkt-hmac-ictx #f opad dctx2)))]))
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
