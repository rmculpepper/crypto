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
         "../private/common/functions.rkt"
         "../private/ssl/factory.rkt"
         "../private/ssl/dh.rkt"
         "../private/cmd-ssl/cmd.rkt"
         "digest.rkt"
         "cipher.rkt"
         "pkey.rkt")
(provide make-ssl-tests
         main)

(define (make-ssl-tests)
  (define (test-dh dhi)
    (test-case (format "DH ~a" (dh-bits dhi))
      (define-values (priv1 pub1) (generate-dhkey dhi))
      (define-values (priv2 pub2) (generate-dhkey dhi))
      (check-equal? (compute-key priv1 pub2)
                    (compute-key priv2 pub1))))
  (test-suite "ssl-based implementation"
    (test-suite "DH"
      (for ([dhi (list dh:192 dh:512 dh:1024 dh:2048 dh:4096)])
        (test-dh dhi)))
    ;; Test ssl impl against cmd-ssl impl
    (test-suite "digests" (test-digests ssl-factory cmdssl-factory))
    (test-suite "cipers" (test-ciphers ssl-factory cmdssl-factory))
    (test-suite "pkey" (test-pkeys ssl-factory cmdssl-factory))))

(define (main)
  (run-tests (make-ssl-tests)))
