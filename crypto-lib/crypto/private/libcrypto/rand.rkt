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
(require racket/class
         ffi/unsafe
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide libcrypto-random-impl%)

(define libcrypto-random-impl%
  (class* impl-base% (random-impl<%>)
    (super-new)
    (define/public (random-bytes! who buf start end)
      (check-output-range who buf start end)
      (void (RAND_bytes (ptr-add buf start) (- end start))))
    (define/public (pseudo-random-bytes! who buf start end)
      (check-output-range who buf start end)
      (void (RAND_pseudo_bytes (ptr-add buf start) (- end start))))))
