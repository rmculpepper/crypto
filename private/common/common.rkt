;; Copyright 2012 Ryan Culpepper
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
(require racket/class
         "interfaces.rkt")
(provide base-ctx%
         shrink-bytes)

;; ----

(define base-ctx%
  (class* object% (ctx<%>)
    (init-field impl)
    (init-field [state 'ready])

    (define/public (get-impl) impl)

    (define/public (get-state) state)
    (define/public (set-state! s) (set! state s))
    (define/public (check-state! who allowed)
      (unless (memq state allowed)
        (error who "called in invalid state: ~e" state)))

    (super-new)))

;; ----

(define (shrink-bytes bs len)
  (if (< len (bytes-length bs))
    (subbytes bs 0 len)
    bs))
