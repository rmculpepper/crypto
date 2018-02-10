;; Copyright 2012-2014 Ryan Culpepper
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

         err/no-impl
         err/bad-signature-pad
         err/bad-encrypt-pad
         err/missing-digest)

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

(define (err/no-impl)
  (crypto-error "internal error: unimplemented"))

(define (err/bad-*-pad kind spec pad)
  (crypto-error "bad ~a padding mode\n  algorithm: ~e\n  padding mode: ~e"
                kind spec pad))
(define (err/bad-signature-pad spec pad)
  (err/bad-*-pad "signature" spec pad))
(define (err/bad-encrypt-pad spec pad)
  (err/bad-*-pad "encryption" spec pad))

(define (err/missing-digest spec)
  (crypto-error "could not get digest implementation\n  digest: ~e" spec))
