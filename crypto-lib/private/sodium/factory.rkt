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
         "cipher.rkt"
         "pkey.rkt"
         "kdf.rkt")
(provide sodium-factory)

(define blake2-digests '(blake2b-512 blake2b-384 blake2b-256 blake2b-160))

(define sodium-factory%
  (class* factory-base% (factory<%>)
    (inherit get-cipher get-kdf print-avail)
    (super-new [ok? (and sodium-ok? (sodium_init))])

    (define/override (get-name) 'sodium)
    (define/override (get-version)
      (and sodium-ok? (version->list (sodium_version_string))))

    (define/override (-get-digest info)
      (define spec (send info get-spec))
      (cond [(and (memq spec blake2-digests) blake2-ok?)
             (new sodium-blake2-digest-impl% (info info) (factory this))]
            [(and (eq? spec 'sha256) sha256-ok?)
             (new sodium-sha256-digest-impl% (info info) (factory this))]
            [(and (eq? spec 'sha512) sha512-ok?)
             (new sodium-sha512-digest-impl% (info info) (factory this))]
            [else #f]))

    (define/override (-get-cipher info)
      (define spec (send info get-spec))
      (define cipher
        (for/first ([rec (in-list cipher-records)]
                    #:when (equal? (aeadcipher-spec rec) spec))
          rec))
      (and cipher (new sodium-cipher-impl% (info info) (factory this) (cipher cipher))))

    (define/override (-get-pk spec)
      (case spec
        [(eddsa) (new sodium-eddsa-impl% (factory this))]
        [(ecx) (new sodium-ecx-impl% (factory this))]
        [else #f]))

    (define/override (-get-pk-reader)
      (new sodium-read-key% (factory this)))

    (define/override (-get-kdf spec)
      (case spec
        [(argon2i)
         (and argon2i-ok? (new sodium-argon2-impl% (factory this) (spec 'argon2i)))]
        [(argon2id)
         (and argon2id-ok? (new sodium-argon2-impl% (factory this) (spec 'argon2id)))]
        [(scrypt)
         (and scrypt-ok? (new sodium-scrypt-impl% (factory this) (spec 'scrypt)))]
        [else #f]))

    ;; ----

    (define/override (info key)
      (case key
        [(version-string) (and sodium-ok? (sodium_version_string))]
        [(all-ec-curves) '()]
        [(all-eddsa-curves) '(ed25519)]
        [(all-ecx-curves) '(x25519)]
        [else (super info key)]))

    (define/override (print-info)
      (printf "Library info:\n")
      (printf " version: ~v\n" (get-version))
      (printf " version string: ~v\n" (info 'version-string))
      (printf " sodium_library_version_major: ~s\n" (sodium_library_version_major))
      (printf " sodium_library_version_minor: ~s\n" (sodium_library_version_minor))
      (print-avail))
    ))

(define sodium-factory (new sodium-factory%))
