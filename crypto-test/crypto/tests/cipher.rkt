;; Copyright 2012-2014 Ryan Culpepper
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
         racket/dict
         racket/port
         rackunit
         crypto/private/common/cipher
         crypto/private/common/catalog
         crypto/private/common/util
         "util.rkt")
(provide test-ciphers
         test-ciphers-agree)

(define (test-ciphers factory)
  (for* ([name (in-hash-keys known-block-ciphers)]
         [mode (map car known-block-modes)])
    (define spec (list name mode))
    (test-cipher/spec factory spec))
  (for ([name (in-hash-keys known-stream-ciphers)])
    (define spec (list name 'stream))
    (test-cipher/spec factory spec)))

(define (test-cipher/spec factory spec)
  (define ci (send factory get-cipher spec))
  (cond [ci
         (when #t
           (eprintf "+  testing ~e\n" spec))
         (for ([in plaintexts])
           (test-cipher ci in))]
        [else
         (when #f
           (eprintf "-  skipping cipher ~e\n" spec))]))

(define (test-cipher ci msg)
  (case (cadr (send ci get-spec))
    [(gcm) (test-cipher/ae ci msg)]
    [else (test-cipher/non-ae ci msg)]))

(define (test-cipher/non-ae ci msg)
  (test-case (format "~a roundtrip (~s)" (send ci get-spec) (bytes-length msg))
    (define key (generate-cipher-key ci #:random semirandom))
    (define iv (generate-cipher-iv ci #:random semirandom))
    (define ciphertext (encrypt ci key iv msg))
    (check-equal? (decrypt ci key iv ciphertext) msg)

    (check-equal? (encrypt ci key iv (open-input-bytes msg))
                  ciphertext)
    (check-equal? (decrypt ci key iv (open-input-bytes ciphertext))
                  msg)

    (let ([cctx (make-encrypt-ctx ci key iv)])
      (check-equal? (bytes-append
                     (apply bytes-append
                            (for/list ([inb (in-bytes msg)])
                              (cipher-update cctx (bytes inb))))
                     (cipher-final cctx))
                    ciphertext))
    (let ([dctx (make-decrypt-ctx ci key iv)])
      (check-equal? (bytes-append
                     (apply bytes-append
                            (for/list ([inb (in-bytes ciphertext)])
                              (cipher-update dctx (bytes inb))))
                     (cipher-final dctx))
                    msg))

    ;; Other keys produce different output, can't decrypt
    (when (positive? (bytes-length ciphertext))
      (define key2 (generate-cipher-key ci #:random semirandom))
      (check-not-equal? (encrypt ci key2 iv msg) ciphertext)
      (check-not-equal? (with-handlers ([values values]) (decrypt ci key2 iv ciphertext))
                        msg))

    ;; If IV, different IV produces different output, can't decrypt
    (when (and (positive? (bytes-length ciphertext))
               (positive? (cipher-iv-size ci)))
      (define iv2 (generate-cipher-iv ci #:random semirandom))
      (check-not-equal? (encrypt ci key iv2 msg) ciphertext)
      (check-not-equal? (with-handlers ([values values]) (decrypt ci key iv2 ciphertext))
                        msg))
    ))

(define (test-cipher/ae ci msg)
  (test-case (format "~a roundtrip (AE, ~s)" (send ci get-spec) (bytes-length msg))
    (define key (generate-cipher-key ci #:random semirandom))
    (define iv (generate-cipher-iv ci #:random semirandom))

    (define-values (ciphertext auth-tag) (encrypt/auth ci key iv msg))
    (check-equal? (decrypt/auth ci key iv ciphertext #:auth-tag auth-tag) msg)

    (let-values ([(c2 at2) (encrypt/auth ci key iv (open-input-bytes msg))])
      (check-equal? c2 ciphertext)
      (check-equal? at2 auth-tag))
    (check-equal? (decrypt/auth ci key iv (open-input-bytes ciphertext) #:auth-tag auth-tag)
                  msg)

    (let ([cctx (make-encrypt-ctx ci key iv)])
      (define cparts (for/list ([inb (in-bytes msg)])
                       (cipher-update cctx (bytes inb))))
      (define-values (last-cpart at2) (cipher-final/tag cctx))
      (check-equal? (bytes-append (apply bytes-append cparts) last-cpart) ciphertext)
      (check-equal? at2 auth-tag))

    (let ([dctx (make-decrypt-ctx ci key iv #:auth-tag auth-tag)])
      (check-equal? (bytes-append
                     (apply bytes-append
                            (for/list ([inb (in-bytes ciphertext)])
                              (cipher-update dctx (bytes inb))))
                     (cipher-final dctx))
                    msg))

    (for ([aad (in-list '(#f #"" #"abc" #"abcdef123456"))])
      (define-values (ciphertext auth-tag) (encrypt/auth ci key iv msg #:AAD aad))
      (check-equal? (decrypt/auth ci key iv ciphertext #:AAD aad #:auth-tag auth-tag) msg))

    (when (positive? (bytes-length ciphertext))
      (define key2 (generate-cipher-key ci #:random semirandom))
      (define iv2 (generate-cipher-iv ci #:random semirandom))
      (define auth-tag2 (semirandom-bytes (bytes-length auth-tag)))
      ;; Other key/iv/auth-tag fails to authenticate
      (check-exn exn:fail? (lambda () (decrypt/auth ci key2 iv ciphertext #:auth-tag auth-tag)))
      (check-exn exn:fail? (lambda () (decrypt/auth ci key iv2 ciphertext #:auth-tag auth-tag)))
      (check-exn exn:fail? (lambda () (decrypt/auth ci key iv ciphertext #:auth-tag auth-tag2))))
    ))

;; ----------------------------------------

(define (test-ciphers-agree factories)
  (for* ([name (in-hash-keys known-block-ciphers)]
         [mode (map car known-block-modes)])
    (define spec (list name mode))
    (test-cipher-agreement spec factories))
  (for ([name (in-hash-keys known-stream-ciphers)])
    (define spec (list name 'stream))
    (test-cipher-agreement spec factories)))

(define (test-cipher-agreement spec factories)
  (let ([names+impls
         (filter cdr
                 (for/list ([factory factories])
                   (cons factory (send factory get-cipher spec))))])
    (when (zero? (length names+impls))
      (eprintf "-  no impl for cipher ~e\n" spec))
    (when (= (length names+impls) 1)
      (eprintf "-  only one impl for cipher ~e\n" spec))
    (when (> (length names+impls) 1)
      (when #t
        (eprintf "+  testing agreement ~e (~s impls)\n" spec (length names+impls)))
      (define names (map car names+impls))
      (define impls (map cdr names+impls))
      (test-case (format "cipher agreement for ~e\n" spec)
        (define key (generate-cipher-key spec #:random semirandom))
        (define iv (generate-cipher-iv spec #:random semirandom))
        (for ([plaintext plaintexts]
              #:when (<= (bytes-length plaintext) 100))
          (define ciphertexts
            (for/list ([impl impls]) (encrypt impl key iv plaintext)))
          (for ([ciphertext ciphertexts]
                [name names])
            (check-equal? ciphertext (car ciphertexts)
                          (format "~e and ~e" name (car names)))))))))

;; ----------------------------------------

(define plaintexts
  `(#""
    #"abc"
    #"I am the walrus."
    ,(semirandom-bytes 10)
    ,(semirandom-bytes 100)
    ,(semirandom-bytes #e1e3)
    ,(semirandom-bytes #e1e4)
    ;; ,(semirandom-bytes #e1e5)
    ))
