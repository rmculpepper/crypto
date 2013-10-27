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
(require (for-syntax racket/base
                     racket/syntax)
         racket/class
         racket/match
         ffi/unsafe
         (only-in "../common/digest.rkt" digest)
         "factory.rkt"
         "ffi.rkt"
         "macros.rkt"
         "rand.rkt"
         "digest.rkt"
         "cipher.rkt"
         "pkey.rkt"
         "dh.rkt")

(provide random-bytes
         pseudo-random-bytes)

(provide-dh)
(provide generate-dhkey)

;; ============================================================
;; Available Digests

(define *digests* null)
(define (available-digests) *digests*)

(define-syntax (define-digest stx)
  (syntax-case stx ()
    [(_ id)
     (with-syntax ([di (format-id stx "digest:~a" #'id)])
       #'(begin
           (define di (send ssl-factory get-digest-by-name 'id))
           (define id (make-digest-op 'id di))
           (when di (set! *digests* (cons di *digests*)))
           (provide di id)))]))

(define (make-digest-op name di)
  (let ([op (if di
                (lambda (inp) (digest di inp))
                (lambda (inp) (error name "unavailable")))])
    (procedure-rename op name)))

(define-digest md5)
(define-digest ripemd160)
(define-digest dss1) ; sha1...
(define-digest sha1)
(define-digest sha224)
(define-digest sha256)
(define-digest sha384)
(define-digest sha512)

(provide available-digests)

;; ============================================================
;; Available Ciphers

(define *ciphers* null)
(define (available-ciphers) *ciphers*)

(define-for-syntax cipher-modes '(ecb cbc cfb ofb))
;; (define-for-syntax default-cipher-mode 'cbc)

;; Full cipher names look like "<FAMILY>(-<PARAM>)?-<MODE>?"
;; where key length is the most common parameter.
;; eg "aes-128-cbc", "bf-ecb", "des-ede-cbc"

(define-syntax define-cipher
  (syntax-rules ()
    [(define-cipher c)
     (define-cipher1 c #f)]
    [(define-cipher c (p ...))
     (begin (define-cipher1 c p) ...)]))

(define-syntax (define-cipher1 stx)
  (syntax-case stx ()
    [(define-cipher1 c klen)
     (with-syntax ([(mode ...) (cons #f cipher-modes)])
       #'(begin (define-cipher1/mode c klen mode) ...))]))

(define-syntax (define-cipher1/mode stx)
  (syntax-case stx ()
    [(define-cipher1/mode c p mode)
     (let* ([p (syntax-e #'p)]
            [mode (syntax-e #'mode)]
            [c-p (if p (format-id #'c "~a-~a" #'c p) #'c)]
            [c-p-mode (if mode (format-id #'c "~a-~a" c-p mode) c-p)])
       (with-syntax ([c-p-mode c-p-mode]
                     [cipher:c-p-mode (format-id #'c "cipher:~a" c-p-mode)])
         #'(begin
             (define cipher:c-p-mode (send ssl-factory get-cipher-by-name 'c-p-mode))
             (provide cipher:c-p-mode))))]))

(define-cipher des (#f ede ede3))
(define-cipher idea)
(define-cipher bf)
(define-cipher cast5)
(define-cipher aes (#f 128 192 256))
(define-cipher camellia (#f 128 192 256))

(define cipher:rc4 (send ssl-factory get-cipher-by-name 'rc4))
(provide cipher:rc4)

(provide available-ciphers)

;; ============================================================
;; Public-Key Available Cryptosystems

(define pkey:rsa (send ssl-factory get-pkey-by-name 'rsa))
(define pkey:dsa (send ssl-factory get-pkey-by-name 'dsa))

(provide pkey:rsa
         pkey:dsa)

;; ============================================================
;; Key Generation

#|
(define (generate-key algo . params)
  (apply (cond [(!cipher? algo) generate-cipher-key]
               [(!pkey? algo) generate-pkey]
               [(!digest? algo) generate-hmac-key]
               [(!dh? algo) generate-dhkey]
               [else (raise-type-error 'generate-key "crypto type" algo)])
         algo params))

(provide generate-key)
|#
