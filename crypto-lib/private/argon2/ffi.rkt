;; Copyright 2017-2018 Ryan Culpepper
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
(require ffi/unsafe
         ffi/unsafe/define
         "../common/error.rkt")
(provide (protect-out (all-defined-out)))

;; Reference: https://github.com/P-H-C/phc-winner-argon2

(define libargon2 (ffi-lib "libargon2" '("1" "0" #f) #:fail (lambda () #f)))
(define-ffi-definer define-argon2 libargon2
  #:default-make-fail make-not-available)

(define argon2-ok?
  (and libargon2
       (get-ffi-obj #"argon2id_hash_raw" libargon2 _fpointer (lambda () #f))
       #t))

(define-argon2 argon2_error_message (_fun _int -> _string/utf-8))

(define argon2-raw-type
  (_fun (t_cost m_cost parallelism pwd salt hashlen) ::
        (t_cost : _uint32)
        (m_cost : _uint32)
        (parallelism : _uint32)
        (pwd : _bytes)
        (pwdlen : _size = (bytes-length pwd))
        (salt : _bytes)
        (saltlen : _size = (bytes-length salt))
        (hash : _bytes = (make-bytes hashlen))
        (hashlen : _size)
        -> (r : _int)
        -> (if (zero? r)
               hash
               (crypto-error "argon2 error: ~a" (argon2_error_message r)))))

(define-argon2 argon2i_hash_raw argon2-raw-type)
(define-argon2 argon2d_hash_raw argon2-raw-type)
(define-argon2 argon2id_hash_raw argon2-raw-type)

(define _argon2_type
  (_enum '(Argon2_d = 0
           Argon2_i = 1
           Argon2_id = 2)))

;; argon2_encodelen includes NUL terminator
(define-argon2 argon2_encodedlen
  (_fun _uint32 _uint32 _uint32 _uint32 _uint32 _argon2_type -> _size))

(define (argon2-enc-type type)
  (_fun (t_cost m_cost parallelism pwd salt hashlen) ::
        (t_cost : _uint32)
        (m_cost : _uint32)
        (parallelism : _uint32)
        (pwd : _bytes)
        (pwdlen : _size = (bytes-length pwd))
        (salt : _bytes)
        (saltlen : _size = (bytes-length salt))
        (hashlen : _size)
        (encoded : _bytes
                 = (make-bytes
                    (argon2_encodedlen t_cost m_cost parallelism
                                       saltlen hashlen type)))
        (encodedlen : _size = (bytes-length encoded))
        -> (r : _int)
        -> (cond [(zero? r) (bytes->string/latin-1 encoded #f 0 (sub1 encodedlen))] ;; remove NUL
                 [else r])))

(define-argon2 argon2i_hash_encoded  (argon2-enc-type 'Argon2_i))
(define-argon2 argon2d_hash_encoded  (argon2-enc-type 'Argon2_d))
(define-argon2 argon2id_hash_encoded (argon2-enc-type 'Argon2_id))

(define argon2-verify-type
  (_fun (encoded pwd) ::
        (encodedz : _string/latin-1 = (string-append encoded "\0"))
        (pwd : _bytes)
        (pwdlen : _size = (bytes-length pwd))
        -> (r : _int) -> (zero? r)))

(define-argon2 argon2i_verify  argon2-verify-type)
(define-argon2 argon2d_verify  argon2-verify-type)
(define-argon2 argon2id_verify argon2-verify-type)
