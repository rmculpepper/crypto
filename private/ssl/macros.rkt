;; mzcrypto: libcrypto bindings for PLT-scheme
;; support macros
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
(require (for-syntax racket/base))
(provide define-symbols
         put-symbols!
         define-provider)

(define-syntax define-symbols
  (syntax-rules ()
    [(define-symbols id)
     (define-syntax id (box null))]
    [(define-symbols id sym ...)
     (begin (define-symbols id) (put-symbols! id sym ...))]))

(define-syntax (put-symbols! stx)
  (syntax-case stx ()
    ((_ tgt sym ...)
     (let ((syms (syntax-local-value #'tgt))
           (cert (syntax-local-certifier)))
       (set-box! syms
         (foldl (lambda (x r)
                  (syntax-case x ()
                    ((id id*) (cons (cons (cert #'id) (cert #'id*)) r))
                    (id (cons (cert #'id) r))))
           (unbox syms) (syntax->list #'(sym ...))))
       #'(begin)))))

(define-syntax (define-provider stx)
  (syntax-case stx ()
    ((_ id tgt)
     (with-syntax (((spec ...)
                    (map (lambda (x)
                           (syntax-case x ()
                             ((id . id*) #'(rename-out (id id*)))
                             (id #'id)))
                      (unbox (syntax-local-value #'tgt)))))
     (syntax/loc stx
       (define-syntax-rule (id)
         (provide spec ...)))))))

(provide let/fini
         let/error)

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
