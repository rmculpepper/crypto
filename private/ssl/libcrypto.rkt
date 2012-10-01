;; mzcrypto: libcrypto bindings for PLT-scheme
;; library definitions
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
(require ffi/unsafe
         ffi/unsafe/define
         ffi/unsafe/atomic
         openssl/libcrypto
         (for-syntax racket/base))

(provide define-crypto

         err-wrap
         err-wrap/check
         err-wrap/pointer

         let/fini
         let/error)

(define-ffi-definer define-crypto libcrypto
  #:default-make-fail make-not-available)

;; ----

(let ()
  (define-crypto ERR_load_crypto_strings (_fun -> _void))
  (define-crypto OpenSSL_add_all_ciphers (_fun -> _void))
  (define-crypto OpenSSL_add_all_digests (_fun -> _void))
  (ERR_load_crypto_strings)
  (OpenSSL_add_all_ciphers)
  (OpenSSL_add_all_digests))

(define-crypto ERR_get_error
  (_fun -> _ulong))
(define-crypto ERR_peek_last_error
  (_fun -> _ulong))
(define-crypto ERR_lib_error_string
  (_fun _ulong -> _string))
(define-crypto ERR_func_error_string
  (_fun _ulong -> _string))
(define-crypto ERR_reason_error_string
  (_fun _ulong -> _string))

;; Use atomic wrapper around ffi calls to avoid race retrieving error info.

(define (err-wrap who ok? [convert values])
  (lambda (proc)
    (lambda args
      (call-as-atomic
       (lambda ()
         (let ([result (apply proc args)])
           (if (ok? result)
               (convert result)
               (raise-crypto-error who))))))))

(define (err-wrap/check who)
  (err-wrap who positive? void))

(define (err-wrap/pointer who)
  (err-wrap who values))

(define (raise-crypto-error where (info #f))
  (let* ([e (ERR_get_error)]
         [le (ERR_lib_error_string e)]
         [fe (and le (ERR_func_error_string e))]
         [re (and fe (ERR_reason_error_string e))])
    (error where "~a [~a:~a:~a]~a~a"
           (or (ERR_reason_error_string e) "?")
           (or (ERR_lib_error_string e) "?")
           (or (ERR_func_error_string e) "?")
           e
           (if info " " "")
           (or info ""))))

;; ----

(define-syntax-rule (with-fini fini body ...)
  (dynamic-wind
    void
    (lambda () body ...)
    (lambda () fini)))

(define-syntax let/fini
  (syntax-rules ()
    [(let/fini () body ...)
     (begin body ...)]
    [(let/fini ((var exp) . rest) body ...)
     (let ((var exp))
       (let/fini rest body ...))]
    [(let/fini ((var exp fini) . rest) body ...)
     (let ((var exp))
       (with-fini (fini var)
         (let/fini rest body ...)))]))

(define-syntax-rule (with-error fini body ...)
  (with-handlers ((void (lambda (e) fini (raise e))))
    body ...))

(define-syntax let/error
  (syntax-rules ()
    [(let/error () body ...)
     (begin body ...)]
    [(let/error ((var exp) . rest) body ...)
     (let ((var exp))
       (self rest body ...))]
    [(let/error ((var exp fini) . rest) body ...)
     (let ((var exp))
       (with-error (fini var)
         (let/error rest body ...)))]))
