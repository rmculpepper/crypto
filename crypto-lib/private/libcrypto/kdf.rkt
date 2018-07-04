;; Copyright 2014-2018 Ryan Culpepper
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
         "../common/common.rkt"
         "../common/kdf.rkt"
         "ffi.rkt")
(provide libcrypto-pbkdf2-impl%)

(define libcrypto-pbkdf2-impl%
  (class kdf-impl-base%
    (init-field di)
    (inherit-field spec)
    (super-new)

    (define/override (kdf config pass salt)
      (define-values (iters key-size)
        (check/ref-config '(iterations key-size) config config:pbkdf2-kdf "PBKDF2"))
      (define key (make-bytes key-size))
      (PKCS5_PBKDF2_HMAC pass salt iters (get-field md di) key)
      key)

    (define/override (pwhash config pass)
      (kdf-pwhash-pbkdf2 this spec config pass))
    (define/override (pwhash-verify pass cred)
      (kdf-pwhash-verify this pass cred))
    ))
