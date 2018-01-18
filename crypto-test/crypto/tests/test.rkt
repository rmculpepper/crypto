;; Copyright 2012 Ryan Culpepper
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
         crypto/libcrypto
         crypto/gcrypt
         crypto/nettle
         crypto/private/cmd-ssl/cmd
         "digest.rkt"
         "cipher.rkt"
         "pkey.rkt")
(provide make-factory-tests)

(define (make-factory-tests name factory)
  (when #t (eprintf ">>> Testing ~a\n" name))
  (test-suite name
    (test-suite "digests" (test-digests factory))
    (test-suite "ciphers" (test-ciphers factory))
    (test-suite "pkey"    (test-pk factory name))
    ))

(module+ main

  (define all-factories (list libcrypto-factory gcrypt-factory nettle-factory #|cmdssl-factory|#))

  (run-tests
   (test-suite "crypto tests"
     (make-factory-tests "libcrypto" libcrypto-factory)
     (make-factory-tests "gcrypt" gcrypt-factory)
     (make-factory-tests "nettle" nettle-factory)
     (when #t (eprintf ">>> Digest agreement\n"))
     (test-suite "digest agreement"
       (test-digests-agree all-factories))
     (when #t (eprintf ">>> Cipher agreement\n"))
     (test-suite "cipher agreement"
       (test-ciphers-agree all-factories))
     (when #t (eprintf ">>> PKey agreement\n"))
     (test-suite "pkey agreement"
       (test-pk libcrypto-factory "libcrypto" all-factories)
       (test-pk gcrypt-factory "gcrypt" all-factories)
       (test-pk nettle-factory "nettle" all-factories))
     )))
