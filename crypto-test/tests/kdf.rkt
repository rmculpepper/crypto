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
         racket/match
         rackunit
         crypto/private/common/interfaces
         crypto/private/common/catalog
         crypto/private/common/kdf
         crypto/private/common/util
         (prefix-in rkt: crypto/private/rkt/pbkdf2)
         "util.rkt")
(provide test-kdfs
         test-kdfs-agree)

(define (test-kdfs factory)
  (for ([name (list-known-kdfs)])
    (match name
      [(list 'pbkdf2 'hmac di)
       (define impl (send factory get-kdf name))
       (define dimpl (send factory get-kdf di))
       (when impl
         (hprintf 1 "testing ~v\n" name)
         (check-equal? (kdf impl key salt '((iterations 2000) (key-size 89)))
                       (rkt:pbkdf2-hmac dimpl key salt 2000 89)))]
      [(or 'argon2i 'argon2d 'argon2id 'scrypt)
       (define impl (send factory get-kdf name))
       (when impl
         (hprintf 1 "testing ~v\n" name)
         (define k (kdf impl key salt (get-config name)))
         (check-pred bytes? k))]
      [_ (void)])))

(define (test-kdfs-agree factories)
  (for ([name (list-known-kdfs)])
    (define config (get-config name))
    (define impls
      (filter values
              (for/list ([factory factories])
                (send factory get-kdf name))))
    (when #f
      (when (zero? (length impls))
        (hprintf -1 "no impl for kdf ~e\n" name)))
    (when (= (length impls) 1)
      (hprintf -1 "only one impl for kdf ~e (~s)\n" name
               (send (send (car impls) get-factory) get-name)))
    (when (> (length impls) 1)
      (hprintf 1 "testing agreement ~e\n" name)
      (test-case (format "~a" name)
        (define impl0 (car impls))
        (define r0 (kdf impl0 key salt config))
        (for ([impl (cdr impls)])
          (check-equal? (kdf impl key salt config) r0))))))

(define (get-config name)
  (match name
    [(list 'pbkdf2 'hmac _)
     `((iterations #e1e4) (key-size 48))]
    ['scrypt
     `((N ,(expt 2 16)) (p 1) (r 8) (key-size 52))]
    [(or 'argon2d 'argon2i 'argon2id)
     `((t 4) (m ,(expt 2 16)) (p 1) (key-size 71))]
    [_ '()]))

(define key #"the morning sun is shining like a red rubber ball")
(define salt #"1234567890123456")
