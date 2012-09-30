;; mzcrypto: libcrypto bindings for PLT-scheme
;; tests
;; 
;; (C) Copyright 2007-2009 Dimitris Vyzovitis <vyzo at media.mit.edu>
;; 
;; mzcrypto is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as published
;; by the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;; 
;; mzcrypto is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Lesser General Public License for more details.
;; 
;; You should have received a copy of the GNU Lesser General Public License
;; along with mzcrypto.  If not, see <http://www.gnu.org/licenses/>.
#lang scheme/base
(require srfi/78
         "main.rkt"
         (only-in "private/util.rkt" hex))
(provide run-tests)

(define (test-sha1)
  (check (hex (sha1 #"")) 
         => #"da39a3ee5e6b4b0d3255bfef95601890afd80709")
  (check (hex (sha1 #"abc")) 
         => #"a9993e364706816aba3e25717850c26c9cd0d89d")
  (check (hex (sha1 #"abcdef")) 
         => #"1f8ac10f23c5b5bc1167bda84b833e5c057a77d2")

  (let ((x (digest-new digest:sha1)))
    (digest-update! x #"abc")
    (check (hex (digest->bytes x))
           => #"a9993e364706816aba3e25717850c26c9cd0d89d")
    (digest-update! x #"abcdef" 3 (bytes-length #"abcdef"))
    (check (hex (digest-final! x))
           => #"1f8ac10f23c5b5bc1167bda84b833e5c057a77d2")))

(define (test-digest dt df)
  (define x (digest-new dt))
  (let* ((bs (random-bytes 128))
         (xbs (df bs)))
    (digest-update! x bs)
    (check (digest->bytes x) => xbs)
    (check (digest-final! x) => xbs))

  (let ((k (random-bytes 20))
        (msg #"The cat is in the box."))
    (check (hmac dt k (open-input-bytes msg)) => (hmac dt k msg))))

(define (test-pubkey ktype dgtype)
  (define k (generate-key ktype 1024))
  (define privkbs (private-key->bytes k))
  (define privk (bytes->private-key ktype privkbs))
  (define pubkbs (public-key->bytes k))
  (define pubk (bytes->public-key ktype pubkbs))

  (check (pkey-private? privk) => #t)
  (check (pkey-private? pubk) => #f)
  (check (= (bytes-length privkbs) (bytes-length pubkbs)) => #f)
  (check (pkey=? k pubk privk) => #t) ; libcrypto cmps only public components

  (let ((x (digest-new dgtype)))
    (digest-update! x (random-bytes 128))
    (check (with-handlers* ((exn:fail? (lambda x 'fail)))
             (digest-sign x pubk)) => 'fail)
    (let ((sig (digest-sign x privk)))
      (check (digest-verify x pubk sig) => #t)))

  (let ((bs (random-bytes 128)))
    (check (with-handlers* ((exn:fail? (lambda x 'fail)))
             (sign pubk dgtype bs)) => 'fail)
    (check (verify pubk dgtype (sign privk dgtype bs) bs) => #t))

  (let ((bs (random-bytes 128)))
    (check (verify pubk dgtype 
                   (sign privk dgtype (open-input-bytes bs)) 
                   (open-input-bytes bs)) 
           => #t)))

(define (test-cipher algo)
  (define msg 
    #"Maybe the cat is out of the box! Where is the cat?")
  (define-values (k iv) (generate-key algo))

  (check (decrypt algo k iv (encrypt algo k iv msg)) => msg)

  (let* ((cin (encrypt algo k iv (open-input-bytes msg)))
         (pin (decrypt algo k iv cin)))
    (check (read-bytes (bytes-length msg) pin) => msg)
    (check (eof-object? (read pin)) => #t))

  (let-values (((pin) (open-input-bytes msg))
               ((cin cout) (make-pipe))
               ((pout) (open-output-bytes)))
    (encrypt algo k iv pin cout)
    (close-output-port cout)
    (decrypt algo k iv cin pout)
    (check (get-output-bytes pout) => msg))

  (let-values (((cin pout) (encrypt algo k iv))
               ((pin cout) (decrypt algo k iv)))
    (write-bytes msg pout)
    (close-output-port pout)
    (write-bytes (read-bytes (* (cipher-block-size algo)
                                (ceiling (/ (bytes-length msg) 
                                            (cipher-block-size algo))))
                             cin)
                 cout)
    (close-output-port cout)
    (check (read-bytes (bytes-length msg) pin) => msg)))

(define (test-encrypt/pkey algo)
  (define privk (generate-key pkey:rsa 1024))
  (define pubk (pkey->public-key privk))
  (define msg #"the cat is still alive...")
  (let ((ct (encrypt/pkey pubk msg)))
    (check (with-handlers* ((exn:fail? (lambda x 'fail)))
             (decrypt/pkey pubk ct)) => 'fail)
    (check (decrypt/pkey privk ct) => msg))
  (let-values (((sk iv ct) (encrypt/envelope pubk algo msg)))
    (check (with-handlers* ((exn:fail? (lambda x 'fail)))
             (decrypt/envelope pubk algo sk iv ct)) => 'fail)
    (check (decrypt/envelope privk algo sk iv ct) => msg)))

  (define (test-dh params)
    (define-values (priv1 pub1) (generate-key params))
    (define-values (priv2 pub2) (generate-key params))
    (check (equal?(compute-key priv1 pub2) (compute-key priv2 pub1)) => #t))

(define (run-tests)
  (define digests 
    (filter values
      (list digest:md5 
            digest:ripemd160
            digest:dss1
            digest:sha1
            digest:sha224
            digest:sha256
            digest:sha384
            digest:sha512)))
  (define hashes
    (filter values
      (list md5 
            ripemd160
            dss1
            sha1
            sha224
            sha256
            sha384
            sha512)))
  (define ciphers
    (filter values
      (list cipher:des
            cipher:des-ede
            cipher:des-ede3
            cipher:idea
            cipher:bf
            cipher:cast5
            cipher:aes-128
            cipher:aes-192
            cipher:aes-256
            cipher:camellia-128
            cipher:camellia-192
            cipher:camellia-256)))

  (define dhparams
    (list dh:192 dh:512 dh:1024 dh:2048 dh:4096))

  (when digest:sha1 (test-sha1))
  (for-each test-digest digests hashes)
  (for-each (lambda (x) (test-pubkey pkey:rsa x)) pkey:rsa:digests)
  (for-each (lambda (x) (test-pubkey pkey:dsa x)) pkey:dsa:digests)
  (for-each test-cipher ciphers)
  (for-each (lambda (x) (test-encrypt/pkey x)) ciphers)
  (for-each test-dh dhparams)

  (check-report))
