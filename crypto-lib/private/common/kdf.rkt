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
         racket/match
         "interfaces.rkt"
         "common.rkt"
         "error.rkt"
         "util.rkt"
         "../rkt/pwhash.rkt")
(provide kdf-impl-base%
         kdf-pwhash-argon2
         kdf-pwhash-scrypt
         kdf-pwhash-pbkdf2
         kdf-pwhash-verify
         config:pbkdf2-base
         config:pbkdf2-kdf
         config:scrypt-pwhash
         config:scrypt-kdf
         config:argon2-base
         config:argon2-kdf)

;; ============================================================
;; KDF and Password Hashing

(define kdf-impl-base%
  (class* impl-base% (kdf-impl<%>)
    (super-new)
    (define/public (kdf params pass salt)
      (err/no-impl this))
    (define/public (pwhash params pass)
      (err/no-impl this))
    (define/public (pwhash-verify pass cred)
      (err/no-impl this))
    ))

(define (kdf-pwhash-argon2 ki config pass)
  (define-values (m t p)
    (check/ref-config '(m t p) config config:argon2-base "argon2"))
  (define alg (send ki get-spec))
  (define salt (crypto-random-bytes 16))
  (define pwh (send ki kdf `((m ,m) (t ,t) (p ,p) (key-size 32)) pass salt))
  (encode (hash '$id alg 'm m 't t 'p p 'salt salt 'pwhash pwh)))

(define (kdf-pwhash-scrypt ki config pass)
  (define-values (ln p r)
    (check/ref-config '(ln p r) config config:scrypt-pwhash "scrypt"))
  (define salt (crypto-random-bytes 16))
  (define pwh (send ki kdf `((N ,(expt 2 ln)) (r ,r) (p ,p) (key-size 32)) pass salt))
  (encode (hash '$id 'scrypt 'ln ln 'r r 'p p 'salt salt 'pwhash pwh)))

(define (kdf-pwhash-pbkdf2 ki spec config pass)
  (define id (or (hash-ref pbkdf2-spec=>id spec #f)
                 (crypto-error "unsupported spec")))
  (define-values (iters)
    (check/ref-config '(iterations) config config:pbkdf2-base "PBKDF2"))
  (define salt (crypto-random-bytes 16))
  (define pwh (send ki kdf `((iterations ,iters) (key-size 32)) pass salt))
  (encode (hash '$id id 'rounds iters 'salt salt 'pwhash pwh)))

(define pbkdf2-spec=>id
  (hash '(pbkdf2 hmac sha1)   'pbkdf2
        '(pbkdf2 hmac sha256) 'pbkdf2-sha256
        '(pbkdf2 hmac sha512) 'pbkdf2-sha512))

(define (kdf-pwhash-verify ki pass cred)
  (define spec (send ki get-spec))
  (define id (peek-id cred))
  (unless (equal? spec (id->kdf-spec id))
    (crypto-error "kdf impl does not support cred id"))
  (define env (parse cred))
  (define config
    (match env
      [(hash-table ['$id (or 'argon2i 'argon2d 'argon2id)] ['m m] ['t t] ['p p])
       `((m ,m) (t ,t) (p ,p) (key-size 32))]
      [(hash-table ['$id (or 'pbkdf2 'pbkdf2-sha256 'pbkdf2-sha512)] ['rounds rounds])
       `((iterations ,rounds) (key-size 32))]
      [(hash-table ['$id 'scrypt] ['ln ln] ['r r] ['p p])
       `((N ,(expt 2 ln)) (r ,r) (p ,p) (key-size 32))]))
  (define salt (hash-ref env 'salt))
  (define pwh (hash-ref env 'pwhash))
  (define pwh* (send ki kdf config pass salt))
  (crypto-bytes=? pwh pwh*))

(define (id->kdf-spec id)
  (case id
    [(argon2i argon2d argon2id scrypt) id]
    [(pbkdf2)        '(pbkdf2 hmac sha1)]
    [(pbkdf2-sha256) '(pbkdf2 hmac sha256)]
    [(pbkdf2-sha512) '(pbkdf2 hmac sha512)]
    [else #f]))

;; ----------------------------------------

;; FIXME: make key-size a param to kdf instead?
(define config:kdf-key-size
  `((key-size   ,exact-positive-integer? #f #:opt 32)))

(define config:pbkdf2-base
  `((iterations ,exact-positive-integer? #f #:req)))

(define config:pbkdf2-kdf
  `(,@config:kdf-key-size
    ,@config:pbkdf2-base))

(define config:scrypt-pwhash
  `((ln ,exact-positive-integer? #f #:req)
    (p  ,exact-positive-integer? #f #:opt 1)
    (r  ,exact-positive-integer? #f #:opt 8)))

(define config:scrypt-kdf
  `(,@config:kdf-key-size
    (N  ,exact-positive-integer? #f #:alt ln)
    (ln ,exact-positive-integer? #f #:alt N)
    (p  ,exact-positive-integer? #f #:opt 1)
    (r  ,exact-positive-integer? #f #:opt 8)))

(define config:argon2-base
  `((t ,exact-positive-integer? #f #:req)
    (m ,exact-positive-integer? #f #:req)
    (p ,exact-positive-integer? #f #:opt 1)))

(define config:argon2-kdf
  `(,@config:kdf-key-size
    ,@config:argon2-base))
