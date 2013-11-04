;; Copyright 2012 Ryan Culpepper
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

(define (test-cipher ci msg)
  (test-case (format "~a roundtrip (~s)" (send ci get-spec) (bytes-length msg))
    (define key (semirandom-bytes (cipher-default-key-size ci)))
    (define iv (semirandom-bytes (cipher-iv-size ci)))
    (define ciphertext (encrypt ci key iv msg))
    (check-equal? (decrypt ci key iv ciphertext) msg)

    ;; Other keys produce different output, can't decrypt
    (when (positive? (bytes-length ciphertext))
      (define key2 (semirandom-bytes (cipher-default-key-size ci)))
      (check-not-equal? (encrypt ci key2 iv msg) ciphertext)
      (check-not-equal? (with-handlers ([values values]) (decrypt ci key2 iv ciphertext))
                        msg))

    ;; If IV, different IV produces different output, can't decrypt
    (when (and (positive? (bytes-length ciphertext))
               (positive? (cipher-iv-size ci)))
      (define iv2 (semirandom-bytes (cipher-iv-size ci)))
      (check-not-equal? (encrypt ci key iv2 msg) ciphertext)
      (check-not-equal? (with-handlers ([values values]) (decrypt ci key iv2 ciphertext))
                        msg))

    ;; (let* ([cin (encrypt ci key iv (open-input-bytes msg))]
    ;;        [pin (decrypt ci key iv cin)])
    ;;   (check-equal? (port->bytes pin) msg))

    ;; (let-values ([(pin) (open-input-bytes msg)]
    ;;              [(cin cout) (make-pipe)]
    ;;              [(pout) (open-output-bytes)])
    ;;   (encrypt ci key iv pin cout)
    ;;   (close-output-port cout)
    ;;   (decrypt ci key iv cin pout)
    ;;   (check-equal? (get-output-bytes pout) msg))

    ;; (let-values ([(cin pout) (encrypt ci key iv)]
    ;;              [(pin cout) (decrypt ci key iv)])
    ;;   (write-bytes msg pout)
    ;;   (close-output-port pout)
    ;;   (write-bytes (port->bytes cin) cout)
    ;;   (close-output-port cout)
    ;;   (check-equal? (port->bytes pin) msg))
    ))

;; ----

(define plaintexts
  `(#""
    #"abc"
    #"I am the walrus."
    ,(semirandom-bytes 10)
    ,(semirandom-bytes 100)
    ,(semirandom-bytes #e1e3)
    ,(semirandom-bytes #e1e4)
    ,(semirandom-bytes #e1e5)
    ))

(define (test-ciphers factory base-factory)
  (for* ([name (in-hash-keys known-block-ciphers)]
         [mode (map car known-block-modes)])
    (define spec (list name mode))
    (test-cipher/spec factory base-factory spec))
  (for ([name (in-hash-keys known-stream-ciphers)])
    (define spec (list name 'stream))
    (test-cipher/spec factory base-factory spec)))

(define (test-cipher/spec factory base-factory spec)
  (define ci (send factory get-cipher spec))
  (define ci-base (send base-factory get-cipher spec))
  (cond [ci ;; (and ci ci-base)
         (when #f
           (eprintf "   testing ~e\n" spec))
         (for ([in plaintexts])
           (test-cipher ci in))]
        [else
         (when #f
           (eprintf "-- skipping cipher ~e\n" spec))]))

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
      (eprintf "** no impl for cipher ~e\n" spec))
    (when (= (length names+impls) 1)
      (eprintf "** only one impl for cipher ~e\n" spec))
    (when (> (length names+impls) 1)
      (when #t
        (eprintf "*  testing agreement ~e (~s impls)\n" spec (length names+impls)))
      (define names (map car names+impls))
      (define impls (map cdr names+impls))
      (test-case (format "cipher agreement for ~e\n" spec)
        (define key (semirandom-bytes (cipher-default-key-size (car impls))))
        (define iv (semirandom-bytes (cipher-iv-size (car impls))))
        (for ([plaintext plaintexts]
              #:when (<= (bytes-length plaintext) 100))
          (define ciphertexts
            (for/list ([impl impls]) (encrypt impl key iv plaintext)))
          (for ([ciphertext ciphertexts]
                [name names])
            (check-equal? ciphertext (car ciphertexts)
                          (format "~e and ~e" name (car names)))))))))
