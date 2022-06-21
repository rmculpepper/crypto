;; Copyright 2012-2018 Ryan Culpepper
;; Copyright 2007-2009 Dimitris Vyzovitis <vyzo at media.mit.edu>
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
         rackunit
         rackunit/text-ui
         crypto
         crypto/all
         "digest.rkt"
         "cipher.rkt"
         "pkey.rkt"
         "kdf.rkt"
         "util.rkt")
(provide (all-defined-out))

(define test-cross? (make-parameter #t))
(define test-pk-keygen? (make-parameter #t))
(define factory-filter (make-parameter (lambda (f) #t)))

(define (make-factory-tests factory #:keygen? [keygen? #f])
  (when ((factory-filter) factory)
    (when #t (hprintf 0 "Testing ~a\n" (send factory get-name)))
    (test-suite (format "~a" (send factory get-name))
      (test-suite "digests" (test-digests factory))
      (test-suite "ciphers" (test-ciphers factory))
      (test-suite "pkey"    (test-pk factory #:keygen? (test-pk-keygen?)))
      (test-suite "kdfs"    (test-kdfs factory))
      )))

(define (go)
  (define the-factories (filter (factory-filter) all-factories))
  (run-tests
   (test-suite "crypto tests"
     (make-factory-tests libcrypto-factory)
     (make-factory-tests gcrypt-factory)
     (make-factory-tests nettle-factory)
     (make-factory-tests b2-factory)
     (make-factory-tests sodium-factory)
     (make-factory-tests argon2-factory)
     (make-factory-tests decaf-factory)
     (when (test-cross?)
       (when #t (hprintf 0 "Digest agreement\n"))
       (test-suite "digest agreement"
         (test-digests-agree the-factories)))
     (when (test-cross?)
       (when #t (hprintf 0 "Cipher agreement\n"))
       (test-suite "cipher agreement"
         (test-ciphers-agree the-factories)))
     (when (test-cross?)
       (when #t (hprintf 0 "PKey agreement\n"))
       (test-suite "pkey agreement"
         (test-pk libcrypto-factory the-factories)
         (test-pk gcrypt-factory the-factories)
         (test-pk nettle-factory the-factories)
         (test-pk sodium-factory the-factories)
         (test-pk decaf-factory the-factories)))
     (when (test-cross?)
       (when #t (hprintf 0 "KDF agreement\n"))
       (test-suite "kdf agreement"
         (test-kdfs-agree the-factories))))))

(module+ main
  (require racket/cmdline)
  (command-line
   #:once-each
   [("-k" "--no-keygen") "No PK keygen and paramgen tests" (test-pk-keygen? #f)]
   [("-c" "--no-cross")  "No cross-testing" (test-cross? #f)]
   #:args factory-name
   (when (pair? factory-name)
     (define ok-names (map string->symbol factory-name))
     (factory-filter (lambda (f) (memq (send f get-name) ok-names))))
   (go)))

(module+ test
  (module config info
    (define timeout 240))
  ;; disable keygen tests to avoid consuming lots of system entropy
  (test-pk-keygen? #f)
  (go))
