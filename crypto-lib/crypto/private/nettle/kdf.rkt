;; Copyright 2014 Ryan Culpepper
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
(provide nettle-pbkdf2-impl%)

;; Nettle's general pbkdf2 function needs hmac_<digest>_{update,digest} functions;
;; not feasible (or at least not easy).

(define nettle-pbkdf2-impl%
  (class* impl-base% (kdf-impl<%>)
    (init-field di)
    (super-new)
    (define/public (kdf params pass salt)
      (define iters (cadr (assq 'iterations params)))
      (define key-size (cadr (assq 'key-size params)))
      (case (send di get-spec)
        [(sha1) (nettle_pbkdf2_hmac_sha1 pass salt iters key-size)]
        [(sha256) (nettle_pbkdf2_hmac_sha256 pass salt iters key-size)]
        [else #f]))
    ))
