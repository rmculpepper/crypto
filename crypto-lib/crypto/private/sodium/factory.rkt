;; Copyright 2018 Ryan Culpepper
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
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "ffi.rkt"
         "cipher.rkt")
(provide sodium-factory)

(define sodium-factory%
  (class* factory-base% (factory<%>)
    (inherit get-cipher)
    (super-new)

    (define/override (get-name) 'sodium)

    (define/override (-get-cipher info)
      (define spec (send info get-spec))
      (define cipher
        (for/first ([rec (in-list cipher-records)]
                    #:when (equal? (aeadcipher-spec rec) spec))
          rec))
      (and cipher (new sodium-cipher-impl% (info info) (factory this) (cipher cipher))))

    ;; ----

    (define/override (info key)
      (case key
        [(version) (and sodium-ok? (sodium_version_string))]
        [(all-digests) null]
        [(all-ciphers) (map aeadcipher-spec cipher-records)]
        [(all-pks) null]
        [(all-curves) null]
        [else (super info key)]))

    (define/override (print-info)
      (printf "Library info:\n")
      (printf " Version: ~v\n" (info 'version))
      (printf "Available ciphers:\n")
      (for ([ci (in-list (info 'all-ciphers))])
        (printf " ~v\n" ci))
      (void))
    ))

(define sodium-factory (new sodium-factory%))
