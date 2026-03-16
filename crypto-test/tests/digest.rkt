;; Copyright 2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         racket/class
         racket/port
         racket/runtime-path
         crypto
         crypto/private/common/catalog
         checkers
         "util.rkt")
(provide test-factory-digests
         xtest-digests
         all-digest-specs
         messages)

(define-runtime-path kat-dir "data/")

(define all-digest-specs
  (sort (hash-keys known-digests) symbol<?))

;; test-factory-digests : Factory -> Void
(define (test-factory-digests factory)
  (test #:name "digests"
    (for ([dspec (in-list all-digest-specs)])
      (define di (get-digest dspec factory))
      (when di
        (test #:name (format "~s" dspec)
          (check di #:with digest-impl?)
          (check (digest-size di) #:no-error)
          (check (digest-block-size di) #:no-error)
          (test-digest-kat dspec di)
          (test-digest-misc dspec di)
          (test-digest-methods-agree dspec di)
          (test-hmac-methods-agree dspec di)))
      (void))))

;; test-digest-kat : DigestSpec DigestImpl -> Void
(define (test-digest-kat dspec di)
  (define kat-file
    (cond [(memq dspec '(sha1
                         sha224 sha256 sha384 sha512
                         sha3-224 sha3-256 sha3-384 sha3-512
                         blake2b-512 blake2s-256))
           (build-path kat-dir (format "digest-~a.rktd" dspec))]
          [(eq? dspec 'sha512/224)
           (build-path kat-dir "digest-sha512_224.rktd")]
          [(eq? dspec 'sha512/256)
           (build-path kat-dir "digest-sha512_256.rktd")]
          [else #f]))
  (when kat-file
    (test #:name "KAT"
      (call-with-input-file kat-file
        (lambda (kat-in)
          (for ([test-datum (in-port read kat-in)])
            (match test-datum
              [(list (== dspec) t-in t-out)
               (check-digest-value di (hex->bytes t-in) #f
                                   (hex->bytes t-out))]
              [(list (== dspec) t-in '#:key t-key t-out)
               (check-digest-value di (hex->bytes t-in) (hex->bytes t-key)
                                   (hex->bytes t-out))])))))))

;; check-digest-value : DigestImpl Bytes Bytes/#f Bytes -> Void
(define (check-digest-value di in key out)
  (check (digest di in #:key key) #:is out))

;; test-digest-methods-agree : DigestSpec DigestImpl -> Void
(define (test-digest-methods-agree dspec di)
  (test #:name "agree"
    (for* ([key (in-list (digest-make-keys di))]
           [msg (in-list messages)])
      ;; One-shot digest
      (define dgst (digest di msg #:key key))
      ;; Ctx with one update
      (let ([ctx (make-digest-ctx di #:key key)])
        (digest-update ctx msg)
        (check (digest-final ctx) #:is dgst))
      ;; Ctx with one update per byte; copy
      (let ([ctx (make-digest-ctx di #:key key)])
        (for ([msgb (in-bytes msg)])
          (define ctx2 (digest-copy ctx))
          (when ctx2
            ;; Check update to ctx2 doesn't affect ctx.
            (digest-update ctx2 (semirandom-bytes (digest-block-size di))))
          (digest-update ctx (bytes msgb)))
        (define peeked (digest-peek-final ctx))
        (when peeked (check peeked #:is dgst))
        (check (digest-final ctx) #:is dgst))
      ;; Ctx with random-sized updates; peek-final
      (let ([ctx (make-digest-ctx di #:key key)])
        (define msglen (bytes-length msg))
        (let loop ([start 0])
          (void (digest-peek-final ctx))
          (when (< start msglen)
            (define end (+ start 1 (random (- msglen start))))
            (digest-update ctx (subbytes msg start end))
            (loop end)))
        (check (digest-final ctx) #:is dgst)))))

;; test-hmac-methods-agree : DigestSpec DigestImpl -> Void
(define (test-hmac-methods-agree dspec di)
  (test #:name "HMAC agree"
    (define key (generate-hmac-key di))
    (for ([msg (in-list messages)])
      ;; One-shot HMAC
      (define tag (hmac di key msg))
      ;; Ctx with one update
      (let ([ctx (make-hmac-ctx di key)])
        (digest-update ctx msg)
        (check (digest-final ctx) #:is tag))
      ;; Ctx with one update per byte; copy
      (let ([ctx (make-hmac-ctx di key)])
        (for ([msgb (in-bytes msg)])
          (define ctx2 (digest-copy ctx))
          (when ctx2
            ;; Check update to ctx2 doesn't affect ctx.
            (digest-update ctx2 (semirandom-bytes (digest-block-size di))))
          (digest-update ctx (bytes msgb)))
        (define tag2 (digest-peek-final ctx))
        (when tag2 (check tag2 #:is tag))
        (check (digest-final ctx) #:is tag)))))

;; test-digest-misc : DigestSpec DigestImpl -> Void
(define (test-digest-misc dspec di)
  (test #:name "misc"
    ;; Check digest treats NUL byte as data, not terminator.
    (for ([key (digest-make-keys di)])
      (check (digest di #"abc" #:key key)
             #:is-not (digest di #"abc\0" #:key key)))))

;; digest-make-keys : DigestImpl -> (Listof Bytes/#f)
(define (digest-make-keys di)
  (append (if (send di key-size-ok? 0) (list #f) '())
          (for/list ([keylen '(16 32)] #:when (send di key-size-ok? keylen))
            (semirandom-bytes keylen))))

;; ============================================================

;; xtest-digests : (Listof Factory) -> Void
(define (xtest-digests factories)
  (test #:name "digests cross"
    (for ([dspec (in-list all-digest-specs)])
      (define (get-di factory) (get-digest dspec factory))
      (define dis (filter values (map get-di factories)))
      (when (> (length dis) 1)
        (define di0 (car dis))
        (test #:name (format "~s (~s)" dspec (length dis))
          (for ([msg (in-list messages)])
            (define dgst (check (digest di0 msg) #:values))
            (for ([di (in-list dis)])
              (check (digest di msg) #:is dgst))
            (define key (generate-hmac-key di0))
            (define tag (check (hmac di0 key msg) #:values))
            (for ([di (in-list dis)])
              (check (hmac di key msg) #:is tag))))))))

;; ============================================================

;; messages : (Listof Bytes)
(define messages
  (list #""
        #"abc"
        (make-bytes 8 #x00)
        (semirandom-bytes 16)
        (semirandom-bytes 50)
        (semirandom-bytes 100)
        (semirandom-bytes 1000)))

;; ============================================================

(define (run-digest-tests factories)
  (for ([factory (in-list factories)])
    (test #:name (format "~s" (send factory get-name))
      (test-factory-digests factory)))
  (xtest-digests factories))

(module+ test
  (require crypto/all)
  (run-digest-tests all-factories))

(module+ main
  (require crypto/all)
  (run-tests (lambda () (run-digest-tests all-factories))
             #:progress? #t))
