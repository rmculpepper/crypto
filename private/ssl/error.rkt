;; mzcrypto: libcrypto bindings for PLT-scheme
;; error handling
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
(provide check-input-range
         check-output-range)

(define check-input-range
  (case-lambda
    [(where bs maxlen)
     (unless (<= (bytes-length bs) maxlen)
       (error where "bad input range"))]
    [(where bs start end)
     (unless (and (<= 0 start) (<= start end) (<= end (bytes-length bs)))
       (error where "bad input range"))]
    [(where bs start end maxlen)
     (unless (and (<= 0 start) (<= start end) (<= end (bytes-length bs))
                  (<= (- end start) maxlen))
       (error where "bad input range"))]))

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
