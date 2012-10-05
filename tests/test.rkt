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
         "../private/common/functions.rkt")
(provide test-digests)

;; let's not exhaust our entropy pool on testing
(define (semirandom-bytes len)
  (let ([bs (make-bytes len)])
    (for ([i (in-range len)])
      (bytes-set! bs i (random 256)))
    bs))

(define (test-digest/in+out di in out)
  (test-case (format "~a: ~s" (send di get-name) in)
    (check-equal? (digest di in) out)
    (check-equal? (digest di (open-input-bytes in)) out)
    (let ([ctx (make-digest-ctx di)])
      (digest-update! ctx in)
      (check-equal? (digest-peek-final ctx) out)
      (check-equal? (digest-final ctx) out))
    (let* ([r 57]
           [in* (bytes-append (make-bytes r 65) in (make-bytes r 66))])
      (let ([ctx (make-digest-ctx di)]
            [dibuf (make-bytes (digest-size di))])
        (digest-update! ctx in* r (+ r (bytes-length in)))
        (digest-final! ctx dibuf 0 (bytes-length dibuf))
        (check-equal? dibuf out))
      (let ([ctx (make-digest-ctx di)])
        (for ([i (in-range r (+ r (bytes-length in)))])
          (digest-update! ctx in* i (add1 i)))
        (check-equal? (digest-final ctx) out)))))

(define (test-digest/ins+outs di ins+outs)
  (test-case (format "incremental ~a" (send di get-name))
    (let ([ctx (make-digest-ctx di)]
          [in-so-far #""])
      (for ([in+out ins+outs])
        (let ([in (car in+out)] [out (cadr in+out)])
          (digest-update! ctx in)
          (set! in-so-far (bytes-append in-so-far in))
          (let ([out-so-far (digest-peek-final ctx)])
            (check-equal? out-so-far out)
            (check-equal? out-so-far (digest in-so-far))))))))

(define (test-digest-impls-agree di di-base in)
  (test-digest/in+out di in (digest di-base in)))

(define (test-hmac/in+out di key in out)
  (test-case (format "HMAC ~a: ~s" (send di get-name) in)
    (check-equal? (hmac di key in) out)
    (check-equal? (hmac di key (open-input-bytes in)) out)
    (let ([ctx (make-hmac-ctx di key)])
      (digest-update! ctx in)
      (check-equal? (digest-final ctx) out))
    (let* ([r 57]
           [in* (bytes-append (make-bytes r 65) in (make-bytes r 66))])
      (let ([ctx (make-hmac-ctx di key)]
            [dibuf (make-bytes (digest-size di))])
        (digest-update! ctx in* r (+ r (bytes-length in)))
        (digest-final! ctx dibuf 0 (bytes-length dibuf))
        (check-equal? dibuf out))
      (let ([ctx (make-hmac-ctx di key)])
        (for ([i (in-range r (+ r (bytes-length in)))])
          (digest-update! ctx in* i (add1 i)))
        (check-equal? (digest-final ctx) out)))))

(define (test-hmac-impls-agree di di-base key in)
  (test-hmac/in+out di key in (hmac di-base key in)))

;; ----

(define (make-sha1-tests digest:sha1)
  (define (td in out) (test-digest/in+out digest:sha1 in out))
  (define (td* ins+outs) (test-digest/ins+outs digest:sha1 ins+outs))
  (test-suite "sha1 tests"
    (td #""
        #"da39a3ee5e6b4b0d3255bfef95601890afd80709")
    (td #"abc"
        #"a9993e364706816aba3e25717850c26c9cd0d89d")
    (td #"abcdef"
        #"1f8ac10f23c5b5bc1167bda84b833e5c057a77d2")
    (td* '((#"abc"
            #"a9993e364706816aba3e25717850c26c9cd0d89d")
           (#"def"
            #"1f8ac10f23c5b5bc1167bda84b833e5c057a77d2")))))

(define digest-inputs
  `(#""
    #"abc"
    #"abcdef"
    #"The cat is in the box."
    #"How now, brown cow?"
    ,(semirandom-bytes 10)
    ,(semirandom-bytes 100)
    ,(semirandom-bytes 1000)
    ,(semirandom-bytes 10000)))

(define digest-keys
  '(#"secret!"))

(define digest-names
  '(sha1 md5 ripemd160 sha224 sha256 sha384 sha512))

(define (test-digests factory base-factory)
  (for ([name digest-names])
    (let ([di (send factory get-digest-by-name name)]
          [di-base (send base-factory get-digest-by-name name)])
      (when (and di di-base)
        (for ([in digest-inputs])
          (test-digest-impls-agree di di-base in))
        (for* ([key digest-keys]
               [in digest-inputs])
          (test-hmac-impls-agree di di-base key in))))))

;; ----

#|

(define (test-pubkey ktype dgtype)
  (define k (generate-pkey ktype 1024))
  (define privkbs (private-key->bytes k))
  (define privk (bytes->private-key ktype privkbs))
  (define pubkbs (public-key->bytes k))
  (define pubk (bytes->public-key ktype pubkbs))

  (check (pkey-private? privk) => #t)
  (check (pkey-private? pubk) => #f)
  (check (= (bytes-length privkbs) (bytes-length pubkbs)) => #f)
  (check (pkey=? k pubk privk) => #t) ; libcrypto cmps only public components

  (let ((x (make-digest-ctx dgtype)))
    (digest-update! x (random-bytes 128))
    (check (with-handlers ((exn:fail? (lambda x 'fail)))
             (digest-sign x pubk)) => 'fail)
    (let ((sig (digest-sign x privk)))
      (check (digest-verify x pubk sig) => #t)))

  (let ((bs (random-bytes 128)))
    (check (with-handlers ((exn:fail? (lambda x 'fail)))
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
  (define-values (k iv) (generate-cipher-key+iv algo))

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
  (define privk (generate-pkey pkey:rsa 1024))
  (define pubk (pkey->public-key privk))
  (define msg #"the cat is still alive...")
  (let ((ct (encrypt/pkey pubk msg)))
    (check (with-handlers ((exn:fail? (lambda x 'fail)))
             (decrypt/pkey pubk ct)) => 'fail)
    (check (decrypt/pkey privk ct) => msg))
  (let-values (((sk iv ct) (encrypt/envelope pubk algo msg)))
    (check (with-handlers ((exn:fail? (lambda x 'fail)))
             (decrypt/envelope pubk algo sk iv ct)) => 'fail)
    (check (decrypt/envelope privk algo sk iv ct) => msg)))

(define (test-dh params)
  (define-values (priv1 pub1) (generate-dhkey params))
  (define-values (priv2 pub2) (generate-dhkey params))
  (check (equal?(compute-key priv1 pub2) (compute-key priv2 pub1)) => #t))

(define (run-tests [flags0 #f])
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

  (define flags
    (or flags0 '(sha1 digests rsa dsa ciphers pkey dh)))

  (when (memq 'sha1 flags)
    (when digest:sha1 (test-sha1)))
  (when (memq 'digests flags)
    (for-each test-digest digests hashes))
  (when (memq 'rsa flags)
    (for ([di digests])
      (when (pkey-digest? pkey:rsa di)
        (test-pubkey pkey:rsa di))))
  (when (memq 'dsa flags)
    (for ([di digests])
      (when (pkey-digest? pkey:dsa di)
        (test-pubkey pkey:dsa di))))
  (when (memq 'ciphers flags)
    (for-each test-cipher ciphers))
  (when (memq 'pkey flags)
    (for-each (lambda (x) (test-encrypt/pkey x)) ciphers))
  (when (memq 'dh flags)
    (for-each test-dh dhparams))

  (check-report))
|#
