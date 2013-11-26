;; Copyright 2012-2013 Ryan Culpepper
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
(require racket/list)
(provide crypto-entry-point
         with-crypto-entry
         crypto-who
         crypto-error
         check-input-range
         check-output-range

         err/digest-closed
         err/cipher-closed
         check-iv-size
         err/bad-iv
         err/key-format
         err/params-format
         err/bad-signature-pad
         err/bad-encrypt-pad
         err/no-direct-keygen
         err/no-sign
         err/no-encrypt
         err/no-key-agree
         err/no-params
         err/sign-requires-private
         err/decrypt-requires-private
         err/missing-digest
         err/missing-cipher
         err/missing-pk)

(define crypto-entry-point (gensym))

(define-syntax-rule (with-crypto-entry who body ...)
  (with-continuation-mark crypto-entry-point who (let () body ...)))

(define (crypto-who)
  (define entry-points
    (continuation-mark-set->list (current-continuation-marks) crypto-entry-point))
  (if (pair? entry-points) (last entry-points) 'crypto))

(define (crypto-error fmt . args)
  (apply error (crypto-who) fmt args))

;; ----

(define (err/digest-closed)
  (crypto-error "digest context is closed"))
(define (err/cipher-closed)
  (crypto-error "cipher context is closed"))

(define (check-iv-size spec iv-size iv)
  (unless (= (if (bytes? iv) (bytes-length iv) 0) iv-size)
    (err/bad-iv spec iv-size iv)))

(define (err/bad-iv spec iv-size iv)
  (crypto-error
   "bad IV size for cipher\n  cipher: ~e\n  expected: ~s bytes\n  got: ~s bytes"
   spec iv-size (if (bytes? iv) (bytes-length iv) 0)))

(define (err/*-format kind spec fmt)
  (crypto-error "~a format not supported\n  algorithm: ~e\n  format: ~e"
                kind spec fmt))
(define (err/key-format spec fmt)
  (err/*-format "key" spec fmt))
(define (err/params-format spec fmt)
  (err/*-format "parameters" spec fmt))

(define (err/bad-*-pad kind spec pad)
  (crypto-error "bad ~a padding mode\n  algorithm: ~e\n  padding mode: ~e"
                kind spec pad))
(define (err/bad-signature-pad spec pad)
  (err/bad-*-pad "signature" spec pad))
(define (err/bad-encrypt-pad spec pad)
  (err/bad-*-pad "encryption" spec pad))

(define (err/no-direct-keygen spec)
  (crypto-error
   (string-append "algorithm does not support direct key generation\n"
                  " generate parameters, then generate key\n"
                  "  algorithm: ~e")
   spec))

(define (err/no-sign spec)
  (crypto-error "signature operations not supported\n  algorithm: ~e" spec))
(define (err/no-encrypt spec)
  (crypto-error "encryption operations not supported\n  algorithm: ~e" spec))
(define (err/no-key-agree spec)
  (crypto-error "key agreement not supported\n  algorithm: ~e" spec))
(define (err/no-params spec)
  (crypto-error "algorithm does not have parameters\n  algorithm: ~e" spec))

(define (err/sign-requires-private)
  (crypto-error "signing requires private key"))
(define (err/decrypt-requires-private)
  (crypto-error "decryption requires private key"))

(define (err/missing-digest spec)
  (crypto-error "could not get digest implementation\n  digest spec: ~e" spec))
(define (err/missing-cipher spec)
  (crypto-error "could not get cipher implementation\n  cipher spec: ~e" spec))
(define (err/missing-pk spec)
  (crypto-error "could not get PK implementation\n  algorithm: ~e" spec))

;; ----

(define (check-input-range buf start end [maxlen #f])
  (unless (and (<= 0 start end (bytes-length buf))
               (or (not maxlen) (<= (- end start) maxlen)))
    (crypto-error
     "bad range for input buffer\n  given: [~a,~a)\n  expected: range within [0,~a)~a"
     start end (bytes-length buf)
     (if maxlen
         (format " of length at most ~a" maxlen)
         ""))))

(define (check-output-range buf start end [minlen #f])
  (when (immutable? buf)
    (crypto-error "expected mutable output buffer"))
  (unless (and (<= 0 start end (bytes-length buf))
               (or (not minlen) (>= (- end start) minlen)))
    (crypto-error
     "bad range for output buffer\n  given: [~a,~a)\n  expected: range within [0,~a)~a"
     start end (bytes-length buf)
     (if minlen
         (format " of length at least ~a" minlen)
         ""))))
