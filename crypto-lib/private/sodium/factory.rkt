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
         "digest.rkt"
         "cipher.rkt")
(provide sodium-factory)

(define blake2-digests '(blake2b-512 blake2b-384 blake2b-256 blake2b-160))

(define sodium-factory%
  (class* factory-base% (factory<%>)
    (inherit get-cipher)
    (super-new [ok? sodium-ok?])

    (define/override (get-name) 'sodium)

    (define/override (-get-digest info)
      (cond [(memq (send info get-spec) blake2-digests)
             (new sodium-blake2-digest-impl% (info info) (factory this))]
            [else #f]))

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
        [(all-digests) blake2-digests]
        [(all-ciphers) (map aeadcipher-spec cipher-records)]
        [(all-pks) null]
        [(all-curves) null]
        [else (super info key)]))

    (define/override (print-info)
      (printf "Library info:\n")
      (printf " Version: ~v\n" (info 'version))
      (printf "Available digests:\n")
      (for ([di (in-list (info 'all-digests))])
        (printf " ~v\n" di))
      (printf "Available ciphers:\n")
      (for ([ci (in-list (info 'all-ciphers))])
        (printf " ~v\n" ci))
      (void))
    ))

(define sodium-factory (new sodium-factory%))
