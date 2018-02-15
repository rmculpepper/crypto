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
         "../common/error.rkt"
         "ffi.rkt")
(provide argon2-factory)

;; ----------------------------------------

(define argon2-kdf-impl%
  (class* impl-base% (kdf-impl<%>)
    (inherit-field spec)
    (super-new)
    (define/public (kdf params pass salt)
      (define (getparam key [default #f])
        (cond [(assq key params) => cadr]
              [default default]
              [else (crypto-error "missing parameter\n  parameter: ~v" key)]))
      (define t (getparam 't))
      (define m (getparam 'm))
      (define p (getparam 'p))
      (define key-size (getparam 'key-size 32))
      (case spec
        [(argon2d)  (argon2d_hash_raw  t m p pass salt key-size)]
        [(argon2i)  (argon2i_hash_raw  t m p pass salt key-size)]
        [(argon2id) (argon2id_hash_raw t m p pass salt key-size)]))))

;; ----------------------------------------

(define argon2-factory%
  (class* factory-base% (factory<%>)
    (inherit get-kdf)
    (super-new [ok? argon2-ok?])

    (define/override (get-name) 'argon2)

    (define/override (-get-kdf spec)
      (case spec
        [(argon2d)  (new argon2-kdf-impl% (factory this) (spec 'argon2d))]
        [(argon2i)  (new argon2-kdf-impl% (factory this) (spec 'argon2i))]
        [(argon2id) (new argon2-kdf-impl% (factory this) (spec 'argon2id))]
        [else #f]))

    (define/override (info key)
      (case key
        [(version) (and argon2-ok? 'unknown)]
        [(all-digests) null]
        [(all-ciphers) null]
        [(all-pks) null]
        [(all-curves) null]
        [(all-kdfs) (filter (lambda (s) (get-kdf s)) '(argon2d argon2i argon2id))]
        [else (super info key)]))

    (define/override (print-info)
      (printf "Library info:\n")
      (printf " Version: ~v\n" (info 'version))
      (printf "Available KDFs:\n")
      (for ([kdf (in-list (info 'all-kdfs))])
        (printf " ~v\n" kdf))
      (void))
    ))

(define argon2-factory (new argon2-factory%))
