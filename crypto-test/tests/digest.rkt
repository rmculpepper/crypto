;; Copyright 2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         racket/class
         racket/port
         racket/runtime-path
         crypto
         crypto/private/common/catalog
         rackunit
         "util.rkt")
(provide make-factory-digest-test
         all-digest-specs
         messages)

(define-runtime-path kat-dir "data/")

(define all-digest-specs
  (sort (hash-keys known-digests) symbol<?))

;; make-factory-digest-test : Factory -> TestSuite
(define (make-factory-digest-test factory)
  (test-suite "digests"
    (hprintf 1 "Digests\n")
    (for ([dspec (in-list all-digest-specs)])
      (define di (get-digest dspec factory))
      (when di
        (test-case (format "~s" dspec)
          (hprintf 2 "~s\n" dspec)
          (check-pred digest-impl? di)
          (void (digest-size di))
          (void (digest-block-size di))
          (check-digest-kat dspec di)
          (check-digest-misc dspec di)
          (check-digest-methods-agree dspec di)
          (check-hmac-methods-agree dspec di)))
      (void))))

;; check-digest-kat : DigestSpec DigestImpl -> Void
(define (check-digest-kat dspec di)
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
    (hprintf 4 "Known-answer tests\n")
    (call-with-input-file kat-file
      (lambda (kat-in)
        (for ([test-datum (in-port read kat-in)])
          (match test-datum
            [(list (== dspec) t-in t-out)
             (check-digest-value di (hex->bytes t-in) #f
                                 (hex->bytes t-out))]
            [(list (== dspec) t-in '#:key t-key t-out)
             (check-digest-value di (hex->bytes t-in) (hex->bytes t-key)
                                 (hex->bytes t-out))]))))))

;; check-digest-value : DigestImpl Bytes Bytes/#f Bytes -> Void
(define (check-digest-value di in key out)
  (check-equal? (digest di in #:key key) out))

;; check-digest-methods-agree : DigestSpec DigestImpl -> Void
(define (check-digest-methods-agree dspec di)
  (hprintf 4 "Method agreement tests\n")
  (for* ([key (in-list (digest-make-keys di))]
         [msg (in-list messages)])
    ;; One-shot digest
    (define dgst (digest di msg #:key key))
    ;; Ctx with one update
    (let ([ctx (make-digest-ctx di #:key key)])
      (digest-update ctx msg)
      (check-equal? (digest-final ctx) dgst))
    ;; Ctx with one update per byte; copy
    (let ([ctx (make-digest-ctx di #:key key)])
      (for ([msgb (in-bytes msg)])
        (define ctx2 (digest-copy ctx))
        (when ctx2
          ;; Check update to ctx2 doesn't affect ctx.
          (digest-update ctx2 (semirandom-bytes (digest-block-size di))))
        (digest-update ctx (bytes msgb)))
      (define peeked (digest-peek-final ctx))
      (when peeked (check-equal? peeked dgst))
      (check-equal? (digest-final ctx) dgst))
    ;; Ctx with random-sized updates; peek-final
    (let ([ctx (make-digest-ctx di #:key key)])
      (define msglen (bytes-length msg))
      (let loop ([start 0])
        (void (digest-peek-final ctx))
        (when (< start msglen)
          (define end (+ start 1 (random (- msglen start))))
          (digest-update ctx (subbytes msg start end))
          (loop end)))
      (check-equal? (digest-final ctx) dgst))))

;; check-hmac-methods-agree : DigestSpec DigestImpl -> Void
(define (check-hmac-methods-agree dspec di)
  (hprintf 4 "HMAC method agreement tests\n")
  (define key (generate-hmac-key di))
  (for ([msg (in-list messages)])
    ;; One-shot HMAC
    (define tag (hmac di key msg))
    ;; Ctx with one update
    (let ([ctx (make-hmac-ctx di key)])
      (digest-update ctx msg)
      (check-equal? (digest-final ctx) tag))
    ;; Ctx with one update per byte; copy
    (let ([ctx (make-hmac-ctx di key)])
      (for ([msgb (in-bytes msg)])
        (define ctx2 (digest-copy ctx))
        (when ctx2
          ;; Check update to ctx2 doesn't affect ctx.
          (digest-update ctx2 (semirandom-bytes (digest-block-size di))))
        (digest-update ctx (bytes msgb)))
      (define tag2 (digest-peek-final ctx))
      (when tag2 (check-equal? tag2 tag))
      (check-equal? (digest-final ctx) tag))))

;; check-digest-misc : DigestSpec DigestImpl -> Void
(define (check-digest-misc dspec di)
  ;; Check digest treats NUL byte as data, not terminator.
  (for ([key (digest-make-keys di)])
    (check-not-equal? (digest di #"abc" #:key key)
                      (digest di #"abc\0" #:key key))))

;; digest-make-keys : DigestImpl -> (Listof Bytes/#f)
(define (digest-make-keys di)
  (append (if (send di key-size-ok? 0) (list #f) '())
          (for/list ([keylen '(16 32)] #:when (send di key-size-ok? keylen))
            (semirandom-bytes keylen))))

;; messages : (Listof Bytes)
(define messages
  (list #""
        #"abc"
        (make-bytes 8 #x00)
        (semirandom-bytes 16)
        (semirandom-bytes 50)
        (semirandom-bytes 100)
        (semirandom-bytes 1000)))
