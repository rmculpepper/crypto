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
(provide check-input-range
         check-output-range)

(define (check-input-range who buf start end [maxlen #f])
  (unless (and (<= 0 start end (bytes-length buf))
               (or (not maxlen) (<= (- end start) maxlen)))
    (error who "bad range for input buffer\n  given: [~a,~a)\n  expected: range within [0,~a)~a"
           start end (bytes-length buf)
           (if maxlen
               (format " of length at most ~a" maxlen)
               ""))))

(define (check-output-range who buf start end [minlen #f])
  (when (immutable? buf)
    (error who "expected mutable output buffer"))
  (unless (and (<= 0 start end (bytes-length buf))
               (or (not minlen) (>= (- end start) minlen)))
    (error who "bad range for output buffer\n  given: [~a,~a)\n  expected: range within [0,~a)~a"
           start end (bytes-length buf)
           (if minlen
               (format " of length at least ~a" minlen)
               ""))))

#|
(define check-input-range
  (case-lambda
    [(where bs maxlen)
     (unless (<= (bytes-length bs) maxlen)
       (error where "bad input range"))]
    [(where bs start end)
     (unless (and (<= 0 start) (<= start end) (<= end (bytes-length bs)))
       (error where "bad input range: [~a,~a); expected range within [0,~a)"
              start end (bytes-length bs)))]
    [(where bs start end maxlen)
     (unless (and (<= 0 start) (<= start end) (<= end (bytes-length bs))
                  (<= (- end start) maxlen))
       (error where "bad input range: [~a,~a); expected range within [0,~a) of length at most ~a"
              start end (bytes-length bs) maxlen))]))
(define check-output-range
  (case-lambda
    [(where bs minlen)
     (when (or (not (bytes? bs)) (immutable? bs))
       (error where "expects mutable bytes"))
     (unless (>= (bytes-length bs) minlen)
       (error where "bad output range"))]
    [(where bs start end)
     (when (or (not (bytes? bs)) (immutable? bs))
       (error where "expects mutable bytes"))
     (unless (and (<= 0 start) (< start end) (<= end (bytes-length bs)))
       (error where "bad output range"))]
    [(where bs start end minlen)
     (when (or (not (bytes? bs)) (immutable? bs))
       (error where "expects mutable bytes"))
     (unless (and (<= 0 start) (< start end) (<= end (bytes-length bs))
                  (>= (- end start) minlen))
       (error where "bad output range"))]))
|#
