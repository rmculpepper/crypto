;; mzcrypto: libcrypto bindings for PLT-scheme
;; main library file
;; 
;; (C) Copyright 2007-2009 Dimitris Vyzovitis <vyzo at media.mit.edu>
;; 
;; mzcrypto is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as published
;; by the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;; 
;; mzcrypto is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Lesser General Public License for more details.
;; 
;; You should have received a copy of the GNU Lesser General Public License
;; along with mzcrypto.  If not, see <http://www.gnu.org/licenses/>.

#lang racket/base
(require (for-syntax racket/base
                     racket/syntax)
         racket/class
         "ffi.rkt"
         "macros.rkt"
         "rand.rkt"
         "digest.rkt"
         "cipher.rkt"
         "pkey.rkt"
         "dh.rkt")

(provide-rand)
(provide-digest)
(provide-cipher)
(provide-pkey)
(provide-dh)

;; ============================================================
;; Available Digests

(define digest-table (make-hasheq))
(define (available-digests) (hash-keys digest-table))

(define (intern-digest-impl name)
  (cond [(hash-ref digest-table name #f)
         => values]
        [(EVP_get_digestbyname (symbol->string name))
         => (lambda (md)
              (let ([di (new digest-impl% (md md) (name name))])
                (hash-set! digest-table name di)
                di))]
        [else #f]))

(define (make-digest-op name di)
  (procedure-rename
   (if di
       (lambda (inp) (digest* di inp))
       (unavailable-function name))
   name))

(define-syntax (define-digest stx)
  (syntax-case stx ()
    [(_ id)
     (with-syntax ([di (format-id stx "digest:~a" #'id)])
       #'(begin
           (define di (intern-digest-impl 'id))
           (define id (make-digest-op 'id di))
           (put-symbols! avail-digests.symbols di id)))]))

(define (unavailable-function who)
  (lambda x (error who "unavailable")))

(define-symbols avail-digests.symbols)

(define-digest md5)
(define-digest ripemd160)
(define-digest dss1) ; sha1...
(define-digest sha1)
(define-digest sha224)
(define-digest sha256)
(define-digest sha384)
(define-digest sha512)

(define-provider provide-avail-digests avail-digests.symbols)
(provide-avail-digests)

;; ============================================================
;; Public Key - Available Digests

;; XXX As of openssl-0.9.8 pkeys can only be used with certain types of
;;     digests.
;;     openssl-0.9.9 is supposed to remove the restriction for digest types
(define pkey:rsa:digests 
  (filter values
    (list digest:ripemd160 
          digest:sha1 digest:sha224 digest:sha256 digest:sha384 digest:sha512)))

(define pkey:dsa:digests
  (filter values
    (list digest:dss1))) ; sha1 with fancy name

(define (pkey-digest? pk dgt)
  (cond [(!pkey? pk)
         (memq dgt
               (cond [(eq? pk pkey:rsa) pkey:rsa:digests]
                     [(eq? pk pkey:dsa) pkey:dsa:digests]
                     [else #f]))]
        [(pkey? pk) (pkey-digest? (-pkey-type pk) dgt)]
        [else (raise-type-error 'pkey-digest? "pkey or pkey type" pk)]))

(provide pkey:rsa:digests
         pkey:dsa:digests
         pkey-digest?)

;; ============================================================
;; Key Generation

(define (generate-key algo . params)
  (apply (cond [(!cipher? algo) generate-cipher-key]
               [(!pkey? algo) generate-pkey]
               [(!digest? algo) generate-hmac-key]
               [(!dh? algo) generate-dhkey]
               [else (raise-type-error 'generate-key "crypto type" algo)])
         algo params))

(provide generate-key)
