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
#lang scheme/base

(require scheme/foreign
         "macros.rkt"
         (for-syntax scheme/base "stx-util.rkt"))
(unsafe!)
(provide ffi-available?
         define/ffi lambda/ffi
         define/alloc let/fini let/error
         unavailable-function
         )

(define libcrypto 
  (case (system-type)
    ((windows) (ffi-lib "libeay32"))
    (else (ffi-lib "libcrypto"))))

(define *silent* #f)

(define-rule (unavailable-function name)
  (lambda x (error 'name "foreign function unavailable")))

(define-rule (unavailable-thunk name)
  (lambda () 
    (unless *silent*
      (fprintf (current-error-port) 
        "warning: foreign function unavailable: ~a~n" 'name))
    (unavailable-function name)))

(define-rule (ffi-available? id)
  (and (get-ffi-obj (@string id) libcrypto _pointer (lambda () #f)) 
       #t))

(define-rule (ffi-lambda id sig)
  (get-ffi-obj (@string id) libcrypto sig (unavailable-thunk id)))

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
  (define/ffi (ERR_load_crypto_strings))
  (define/ffi (OpenSSL_add_all_ciphers))
  (define/ffi (OpenSSL_add_all_digests))
    
  (ERR_load_crypto_strings)
  (OpenSSL_add_all_ciphers)
  (OpenSSL_add_all_digests)
  )
