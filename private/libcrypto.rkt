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
         openssl/libcrypto
         "macros.rkt"
         (for-syntax racket/base
                     "stx-util.rkt"))
(provide define-crypto
         ffi-available?
         define/ffi lambda/ffi
         define/alloc let/fini let/error)

(define-ffi-definer define-crypto libcrypto
  #:default-make-fail make-not-available)

(define-rule (ffi-available? id)
  (and (get-ffi-obj (@string id) libcrypto _pointer (lambda () #f)) 
       #t))

(define-rule (ffi-lambda id sig)
  (get-ffi-obj (@string id) libcrypto sig))

(define-rules lambda/ffi (: ->)
  ((_ (id args ...))
   (ffi-lambda id (_fun args ... -> _void)))
  ((_ (id args ...) -> type)
   (ffi-lambda id (_fun args ... -> type)))
  ((_ (id args ...) -> type : guard)
   (ffi-lambda id (_fun args ... -> (r : type) -> (guard 'id r)))))

(define-rule (define/ffi (f args ...) rest ...)
  (define f (lambda/ffi (f args ...) rest ...)))

(define-syntax (define/alloc stx)
  (syntax-case stx ()
    ((_ id)
     (with-syntax ((new (/identifier stx #'id "_new"))
                   (free (/identifier stx #'id "_free")))
       #'(begin
           (define new
             (ffi-lambda new
               (_fun -> (r : _pointer)
                     -> (if r r (error 'new "libcrypto: out of memory")))))
           (define free
             (ffi-lambda free 
               (_fun _pointer -> _void))))))))

(define-rule (with-fini fini body ...)
  (dynamic-wind
    void
    (lambda () body ...)
    (lambda () fini)))

(define-rules let/fini ()
  ((_ () body ...) (begin body ...))
  ((self ((var exp) . rest) body ...)
   (let ((var exp))
     (self rest body ...)))
  ((self ((var exp fini) . rest) body ...)
   (let ((var exp))
     (with-fini (fini var)
       (self rest body ...)))))

(define-rule (with-error fini body ...)
  (with-handlers ((void (lambda (e) fini (raise e))))
    body ...))

(define-rules let/error ()
  ((_ () body ...) (begin body ...))
  ((self ((var exp) . rest) body ...)
   (let ((var exp))
     (self rest body ...)))
  ((self ((var exp fini) . rest) body ...)
   (let ((var exp))
     (with-error (fini var)
       (self rest body ...)))))

(let ()
  (define-crypto ERR_load_crypto_strings (_fun -> _void))
  (define-crypto OpenSSL_add_all_ciphers (_fun -> _void))
  (define-crypto OpenSSL_add_all_digests (_fun -> _void))
  (ERR_load_crypto_strings)
  (OpenSSL_add_all_ciphers)
  (OpenSSL_add_all_digests))
