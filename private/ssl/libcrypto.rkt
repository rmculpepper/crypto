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
