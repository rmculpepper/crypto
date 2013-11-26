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
         check-output-range)

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
