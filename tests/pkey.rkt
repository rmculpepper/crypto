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
         racket/port
         rackunit
         "../private/common/functions.rkt"
         "digest.rkt"
         "cipher.rkt")
(provide test-pkeys)

;; digest-names, digest-inputs
(define (test-pubkey pki di)
  (test-case (format "~a with ~a" (send pki get-name) (send di get-name))
    (define k (send pki generate-key '(1024)))
    (define privkbs (private-key->bytes k))
    (define privk (bytes->private-key pki privkbs))
    (define pubkbs (public-key->bytes k))
    (define pubk (bytes->public-key pki pubkbs))

    (check-equal? (pkey-private? privk) #t)
    (check-equal? (pkey-private? pubk)  #f)
    (check-not-equal? (bytes-length privkbs) (bytes-length pubkbs))
    (check pkey=? k pubk)
    (check pkey=? k privk) ;; libcrypto cmps only public components (???)

    (for ([msg digest-inputs])
      (let ([ctx (make-digest-ctx di)])
        (digest-update! ctx msg)
        (check-exn exn:fail? (lambda () (digest-sign ctx pubk)))
        (let ([sig (digest-sign ctx privk)])
          (check-equal? (digest-verify ctx pubk sig) #t))))

    (for ([msg digest-inputs])
      (check-exn exn:fail? (lambda () (sign pubk di msg)))
      (check-equal? (verify pubk di (sign privk di msg) msg) #t))

    (for ([msg digest-inputs])
      (check-equal? (verify pubk di
                            (sign privk di (open-input-bytes msg))
                            (open-input-bytes msg))
                    #t))
    ))

(define (test-encrypt/pkey pki pkey-ciphers)
  (test-case (format "~a encryption" (send pki get-name))
    (define privk (send pki generate-key '(1024)))
    (define pubk (pkey->public-key privk))
    (define msg #"The cat is still alive...")
    (let ([ct (encrypt/pkey pubk msg)])
      (check-exn exn:fail? (lambda () (decrypt/pkey pubk ct)))
      (check-equal? (decrypt/pkey privk ct) msg))
    (for ([ci pkey-ciphers])
      (let-values ([(sk iv ct) (encrypt/envelope pubk ci msg)])
        (check-exn exn:fail? (lambda () (decrypt/envelope pubk ci sk iv ct)))
        (check-equal? (decrypt/envelope privk ci sk iv ct) msg)))))

;; ----

(define pkey-names '(rsa dsa))

(define (test-pkeys factory base-factory)
  (for ([name pkey-names])
    (let ([pki (send factory get-pkey-by-name name)]
          [base-pki (send base-factory get-pkey-by-name name)])
      (when pki
        (for ([di-name digest-names])
          (let ([di (send factory get-digest-by-name di-name)]
                [base-di (and base-factory (send base-factory get-digest-by-name di-name))])
            (when (pkey-digest? pki di)
              (when #f (eprintf "** Testing ~a with ~a\n" name di-name))
              (test-pubkey pki di))))
        (when (pkey-can-encrypt? pki)
          (test-encrypt/pkey pki
                             (for/list ([cn '(aes-128-cbc aes-128-ecb bf-cbc)])
                               (send factory get-cipher-by-name cn))))))))

;; FIXME: to test agreement of implementations, need representation of keys
;; to be compatible (or at least convertible)
