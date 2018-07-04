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
         "../common/factory.rkt"
         "../common/kdf.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide argon2-factory)

;; ----------------------------------------

(define argon2-kdf-impl%
  (class kdf-impl-base%
    (inherit-field spec)
    (super-new)

    (define/override (kdf config pass salt)
      (define-values (t m p key-size)
        (check/ref-config '(t m p key-size) config config:argon2-kdf "argon2"))
      (case spec
        [(argon2d)  (argon2d_hash_raw  t m p pass salt key-size)]
        [(argon2i)  (argon2i_hash_raw  t m p pass salt key-size)]
        [(argon2id) (argon2id_hash_raw t m p pass salt key-size)]))

    (define/override (pwhash config pass)
      (define-values (t m p)
        (check/ref-config '(t m p) config config:argon2-base "argon2"))
      (define key-size 32)
      (define salt (crypto-random-bytes 16))
      (define cred
        (case spec
          [(argon2d)  (argon2d_hash_encoded  t m p pass salt key-size)]
          [(argon2i)  (argon2i_hash_encoded  t m p pass salt key-size)]
          [(argon2id) (argon2id_hash_encoded t m p pass salt key-size)]))
      (cond [(string? cred) cred]
            [else (crypto-error "failed")]))

    (define/override (pwhash-verify pass cred)
      (case spec
        [(argon2d)  (argon2d_verify  cred pass)]
        [(argon2i)  (argon2i_verify  cred pass)]
        [(argon2id) (argon2id_verify cred pass)]))
    ))

;; ----------------------------------------

(define argon2-factory%
  (class* factory-base% (factory<%>)
    (inherit get-kdf print-avail)
    (super-new [ok? argon2-ok?])

    (define/override (get-name) 'argon2)
    (define/override (get-version) (and argon2-ok? '()))

    (define/override (-get-kdf spec)
      (case spec
        [(argon2d)  (new argon2-kdf-impl% (factory this) (spec 'argon2d))]
        [(argon2i)  (new argon2-kdf-impl% (factory this) (spec 'argon2i))]
        [(argon2id) (new argon2-kdf-impl% (factory this) (spec 'argon2id))]
        [else #f]))

    (define/override (info key)
      (case key
        [(all-kdfs) (filter (lambda (s) (get-kdf s)) '(argon2d argon2i argon2id))]
        [else (super info key)]))

    (define/override (print-info)
      (printf "Library info:\n")
      (printf " version: ~v\n" (get-version))
      (print-avail))
    ))

(define argon2-factory (new argon2-factory%))
