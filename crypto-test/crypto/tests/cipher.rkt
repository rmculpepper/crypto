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
         make-cipher-agreement-tests)

(define (test-cipher/roundtrip ci key iv msg)
  (test-case (format "~a roundtrip (~s)" (send ci get-spec) (bytes-length msg))

    (check-equal? (decrypt ci key iv (encrypt ci key iv msg))
                  msg)

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
         (define key (semirandom-bytes (cipher-default-key-size ci)))
         (define iv (semirandom-bytes (cipher-iv-size ci)))
         (eprintf "   testing ~e\n" spec)
         (for ([in plaintexts])
           (test-cipher/roundtrip ci key iv in))]
        [else
         (when #t
           (eprintf "-- skipping cipher ~e\n" spec))]))

(define (make-cipher-agreement-tests factories)
  (test-suite "cipher agreement"
    (for ([name (in-hash-keys known-block-ciphers)]
          [mode (map car known-block-modes)])
      (define spec (list name mode))
      (test-cipher-agreement spec factories))
    (for ([name (in-hash-keys known-stream-ciphers)])
      (define spec (list name 'stream))
      (test-cipher-agreement spec factories))))

(define (test-cipher-agreement spec factories)
  (let ([names+impls
         (filter cdr
                 (for/list ([factory factories])
                   (cons factory (send factory get-cipher spec))))])
    (when (> (length names+impls) 1)
      (eprintf "*  testing agreement ~e\n" spec)
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
