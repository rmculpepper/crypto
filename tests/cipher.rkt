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
         racket/dict
         racket/port
         rackunit
         "../private/common/functions.rkt"
         "util.rkt")
(provide test-ciphers)

(define (test-cipher/roundtrip ci key iv msg)
  (test-case (format "~a roundtrip ~e" (send ci get-name) msg)

    (check-equal? (decrypt ci key iv (encrypt ci key iv msg))
                  msg)

    (let* ([cin (encrypt ci key iv (open-input-bytes msg))]
           [pin (decrypt ci key iv cin)])
      (check-equal? (port->bytes pin) msg))

    (let-values ([(pin) (open-input-bytes msg)]
                 [(cin cout) (make-pipe)]
                 [(pout) (open-output-bytes)])
      (encrypt ci key iv pin cout)
      (close-output-port cout)
      (decrypt ci key iv cin pout)
      (check-equal? (get-output-bytes pout) msg))

    (let-values ([(cin pout) (encrypt ci key iv)]
                 [(pin cout) (decrypt ci key iv)])
      (write-bytes msg pout)
      (close-output-port pout)
      (write-bytes (port->bytes cin) cout)
      (close-output-port cout)
      (check-equal? (port->bytes pin) msg))
    ))

;; ----

(define cipher-names
  '(aes-128-cbc    aes-128-ecb
    aes-192-cbc    aes-192-ecb
    aes-256-cbc    aes-256-ecb
    base64
    bf-cbc         bf-cfb         bf-ecb         bf-ofb
    cast-cbc
    cast5-cbc      cast5-cfb      cast5-ecb      cast5-ofb
    des-cbc        des-cfb        des-ecb        des-ofb
    des-ede        des-ede-cbc    des-ede-cfb    des-ede-ofb
    des-ede3       des-ede3-cbc   des-ede3-cfb   des-ede3-ofb
    desx
    rc2-cbc        rc2-cfb        rc2-ecb        rc2-ofb
    rc2-40-cbc     rc2-64-cbc
    rc4            rc4-40
    ))

(define plaintexts
  `(#""
    #"abc"
    #"I am the walrus."
    ,(semirandom-bytes 10)
    ,(semirandom-bytes 100)
    ,(semirandom-bytes #e1e3)
    ,(semirandom-bytes #e1e4)
    ,(semirandom-bytes #e1e5)
    ))

(define (test-ciphers factory base-factory)
  (for ([name cipher-names])
    (let ([ci (send factory get-cipher-by-name name)]
          [ci-base (send base-factory get-cipher-by-name name)])
      (cond [(and ci ci-base)
             ;; Use base-factory to generate key in case it has special restrictions
             (let-values ([(key iv) (send ci-base generate-key+iv)])
               (for ([in plaintexts])
                 (test-cipher/roundtrip ci key iv in)))]
            [else
             (when #f
               (eprintf "** Skipping cipher ~s\n" name))]))))
