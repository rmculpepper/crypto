;; Copyright 2012-2018 Ryan Culpepper
;; Copyright 2007-2009 Dimitris Vyzovitis <vyzo at media.mit.edu>
;; 
;; This library is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as published
;; by the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;; 
;; This library is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Lesser General Public License for more details.
;; 
;; You should have received a copy of the GNU Lesser General Public License
;; along with this library.  If not, see <http://www.gnu.org/licenses/>.

#lang racket/base
(require racket/class
         rackunit
         crypto
         crypto/private/common/interfaces
         crypto/private/common/catalog
         "util.rkt")
(provide (all-defined-out))

(define (test-ciphers factory)
  (for* ([name (sort (hash-keys known-block-ciphers) symbol<?)]
         [mode (sort known-block-modes symbol<?)])
    (define spec (list name mode))
    (when (cipher-spec? spec)
      (test-cipher/spec factory spec)))
  (for ([name (sort (hash-keys known-stream-ciphers) symbol<?)])
    (define spec (list name 'stream))
    (test-cipher/spec factory spec)))

(define (test-cipher/spec factory spec)
  (define ci (send factory get-cipher spec))
  (cond [ci
         (hprintf 1 "testing ~e\n" spec)
         (test-cipher-meta spec)
         (test-cipher-meta ci)
         (for ([in plaintexts])
           (test-cipher ci in))]
        [else
         (when #f
           (hprintf -1 "skipping cipher ~e\n" spec))]))

(define (test-cipher-meta ci)
  (cipher-default-key-size ci)
  (unless (cipher-ctx? ci)
    (cipher-key-sizes ci))
  (cipher-block-size ci)
  (cipher-iv-size ci)
  (cipher-aead? ci)
  (cipher-default-auth-size ci)
  (when (or (cipher-impl? ci) (cipher-ctx? ci))
    (cipher-chunk-size ci)))

(define (test-cipher ci msg)
  (test-cipher/attached ci msg)
  (test-cipher/detached ci msg))

(define (test-cipher/attached ci msg)
  (test-case (format "~a roundtrip (~s)" (send ci get-spec) (bytes-length msg))
    (define key (generate-cipher-key ci))
    (define iv (generate-cipher-iv ci))

    (define ciphertext (encrypt ci key iv msg))
    (check-equal? (encrypt ci key iv (open-input-bytes msg)) ciphertext)

    (check-equal? (decrypt ci key iv ciphertext) msg)
    (check-equal? (decrypt ci key iv (open-input-bytes ciphertext)) msg)

    (let ([cctx (make-encrypt-ctx ci key iv #:auth-attached? #f)])
      (test-cipher-meta cctx)
      (check-equal? (bytes-append
                     (apply bytes-append
                            (for/list ([inb (in-bytes msg)])
                              (cipher-update cctx (bytes inb))))
                     (cipher-final cctx)
                     (or (cipher-get-auth-tag cctx) #""))
                    ciphertext))
    (let ([dctx (make-decrypt-ctx ci key iv #:auth-attached? #t)])
      (check-equal? (bytes-append
                     (apply bytes-append
                            (for/list ([inb (in-bytes ciphertext)])
                              (cipher-update dctx (bytes inb))))
                     (cipher-final dctx))
                    msg))

    (when (> (cipher-block-size ci) 1)
      (define msg (make-bytes (+ (* (cipher-block-size ci) 4) 1) (char->integer #\a)))
      (check-exn #rx"input size not a multiple of block size"
                 (lambda () (encrypt ci key iv msg #:pad #f)))
      (unless (cipher-aead? ci)
        (check-exn #rx"input size not a multiple of block size"
                   (lambda () (decrypt ci key iv msg #:pad #f)))))

    ;; Other keys produce different output, can't decrypt
    (when (positive? (bytes-length msg))
      (define key2 (generate-cipher-key ci))
      (check-not-equal? (encrypt ci key2 iv msg) ciphertext)
      (check-not-equal? (with-handlers ([values values]) (decrypt ci key2 iv ciphertext))
                        msg))

    ;; If IV, different IV produces different output, can't decrypt
    (when (and (positive? (bytes-length msg))
               (positive? (cipher-iv-size ci)))
      (define iv2 (generate-cipher-iv ci))
      (check-not-equal? (encrypt ci key iv2 msg) ciphertext)
      (check-not-equal? (with-handlers ([values values]) (decrypt ci key iv2 ciphertext))
                        msg))

    (when (cipher-aead? ci)
      (for ([aad (in-list '(() #"" #"abc" #"abcdef123456"))])
        (define ct (encrypt ci key iv msg #:aad aad))
        (check-equal? (decrypt ci key iv ct #:aad aad) msg)
        (check-exn #rx"authenticated decryption failed"
                   (lambda () (decrypt ci key iv ct #:aad "bad")))))
    ))

(define (test-cipher/detached ci msg)
  (test-case (format "~a roundtrip (detached, ~s)" (send ci get-spec) (bytes-length msg))
    (define key (generate-cipher-key ci))
    (define iv (generate-cipher-iv ci))

    (define-values (ciphertext auth-tag) (encrypt/auth ci key iv msg))
    (check-equal? (decrypt/auth ci key iv ciphertext #:auth-tag auth-tag) msg)

    (let-values ([(c2 at2) (encrypt/auth ci key iv (open-input-bytes msg))])
      (check-equal? c2 ciphertext)
      (check-equal? at2 auth-tag))
    (check-equal? (decrypt/auth ci key iv (open-input-bytes ciphertext) #:auth-tag auth-tag) msg)

    (let ([cctx (make-encrypt-ctx ci key iv #:auth-attached? #f)])
      (define cparts (append (for/list ([inb (in-bytes msg)])
                               (cipher-update cctx (bytes inb)))
                             (list (cipher-final cctx))))
      (define at2 (cipher-get-auth-tag cctx))
      (check-equal? (apply bytes-append cparts) ciphertext)
      (check-equal? at2 auth-tag))

    (let ([dctx (make-decrypt-ctx ci key iv #:auth-attached? #f)])
      (check-equal? (bytes-append
                     (apply bytes-append
                            (for/list ([inb (in-bytes ciphertext)])
                              (cipher-update dctx (bytes inb))))
                     (cipher-final dctx auth-tag))
                    msg))

    (check-equal? (decrypt ci key iv (list ciphertext auth-tag)) msg)

    (when (cipher-aead? ci)
      (for ([aad (in-list '(() #"" #"abc" #"abcdef123456"))])
        (define-values (ciphertext auth-tag) (encrypt/auth ci key iv msg #:aad aad))
        (check-equal? (decrypt/auth ci key iv ciphertext #:aad aad #:auth-tag auth-tag) msg))
      (when (positive? (bytes-length ciphertext))
        (define key2 (generate-cipher-key ci))
        (define iv2 (generate-cipher-iv ci))
        (define auth-tag2 (semirandom-bytes (bytes-length auth-tag)))
        ;; Other key/iv/auth-tag fails to authenticate
        (check-exn exn:fail? (lambda () (decrypt/auth ci key2 iv ciphertext #:auth-tag auth-tag)))
        (check-exn exn:fail? (lambda () (decrypt/auth ci key iv2 ciphertext #:auth-tag auth-tag)))
        (check-exn exn:fail? (lambda () (decrypt/auth ci key iv ciphertext #:auth-tag auth-tag2)))))
    ))

;; ----------------------------------------

(define (test-ciphers-agree factories)
  (for* ([name (sort (hash-keys known-block-ciphers) symbol<?)]
         [mode (sort known-block-modes symbol<?)])
    (define spec (list name mode))
    (when (cipher-spec? spec)
      (test-cipher-agreement spec factories)))
  (for ([name (sort (hash-keys known-stream-ciphers) symbol<?)])
    (define spec (list name 'stream))
    (test-cipher-agreement spec factories)))

(define (test-cipher-agreement spec factories)
  (let ([factories+impls
         (filter cdr
                 (for/list ([factory factories])
                   (cons factory (send factory get-cipher spec))))])
    (define factories (map car factories+impls))
    (define impls (map cdr factories+impls))
    (when (zero? (length impls))
      (hprintf -1 "no impl for cipher ~e\n" spec))
    (when (= (length impls) 1)
      (hprintf -1 "only one impl for cipher ~e\n" spec))
    (when (> (length impls) 1)
      (when #t
        (hprintf 1 "testing agreement ~e (~s impls)\n" spec (length impls)))
      (test-case (format "cipher agreement for ~e\n" spec)
        (define key (generate-cipher-key spec))
        (define iv (generate-cipher-iv spec))
        (for ([plaintext plaintexts] #:when (<= (bytes-length plaintext) 100))
          ;; skip impls that don't support chosen key length
          (define ciphertexts
            (for/list ([impl impls])
              (and (send impl key-size-ok? (bytes-length key))
                   (encrypt impl key iv plaintext))))
          (for ([ciphertext ciphertexts]
                [factory factories]
                #:when ciphertext)
            (check-equal? ciphertext (car ciphertexts)
                          (format "~e and ~e"
                                  (send factory get-name)
                                  (send (car factories) get-name)))))))))

;; ----------------------------------------

(define plaintexts
  `(#""
    #"abc"
    #"I am the walrus."
    ,(semirandom-bytes 10)
    ,(semirandom-bytes 16)
    ,(semirandom-bytes 31)
    ,(semirandom-bytes 32)
    ,(semirandom-bytes 33)
    ,(semirandom-bytes 100)
    ,(semirandom-bytes #e1e3)
    ,(semirandom-bytes #e1e4)
    ;; ,(semirandom-bytes #e1e5)
    ))
