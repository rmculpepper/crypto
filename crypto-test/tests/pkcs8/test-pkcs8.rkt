#lang racket/base
(require racket/file
         racket/port
         racket/class
         racket/system
         crypto
         crypto/all
         crypto/pkcs8
         racket/runtime-path
         rackunit)

(define-runtime-path here ".")

(define passwd #"password")
(define key-der (file->bytes (build-path here "rsa.der")))
(define key-pem (file->bytes (build-path here "rsa.p8.pem")))

(define openssl (find-executable-path "openssl"))
(define openssl-version
  (if openssl (with-output-to-string (lambda () (system* openssl "version"))) ""))
(unless openssl
  (printf "-- skipping all openssl command tests\n"))

(define-syntax-rule (test-if kdf cipher body ...)
  (cond [(and (get-kdf kdf) (get-cipher cipher))
         (printf "   running ~s ~s tests\n" kdf cipher)
         body ...]
        [else (printf "-  skipping ~s ~s tests\n" kdf cipher)]))

(define (test-p8-file p8-file)
  ;; (printf "+  testing ~s\n" p8-file)
  (check-equal?
   (pkcs8-decrypt-bytes passwd (file->bytes (build-path here p8-file)))
   key-der))

(define (test-decrypt p8 #:openssl [openssl-rx #""])
  ;; (printf "+  testing roundtrip\n")
  (check-equal? (pkcs8-decrypt-bytes passwd p8) key-der)
  (when (and openssl (regexp-match openssl-rx openssl-version))
    (check-equal? (openssl-decrypt p8) key-pem)))

(define (openssl-decrypt p8)
  (with-output-to-bytes
    (lambda ()
      (parameterize ((current-input-port (open-input-bytes p8)))
        (system* openssl "pkcs8"
                 "-passin" (format "pass:~a" passwd)
                 "-inform" "DER" "-outform" "PEM")))))

(for ([factory all-factories])
  (printf ">> testing ~a\n" (send factory get-name))
  (parameterize ((crypto-factories factory))
    (test-if '(pbkdf2 hmac sha1) '(des-ede3 cbc)
             (test-p8-file "rsa.des3-sha1.p8")
             (test-decrypt
              (pkcs8-encrypt/pbkdf2-hmac
               passwd key-der #:digest 'sha1 #:cipher '(des-ede3 cbc))))
    (test-if '(pbkdf2 hmac sha1) '(aes cbc)
             (test-p8-file "rsa.aes128-sha1.p8")
             (test-decrypt
              (pkcs8-encrypt/pbkdf2-hmac
               passwd key-der #:digest 'sha1 #:cipher '(aes cbc) #:key-size 16)))
    (test-if '(pbkdf2 hmac sha256) '(aes cbc)
             (test-p8-file "rsa.aes128-sha256.p8")
             (pkcs8-encrypt/pbkdf2-hmac
              passwd key-der #:digest 'sha256 #:cipher '(aes cbc) #:key-size 16))
    (test-if 'scrypt '(aes cbc)
             (test-p8-file "rsa.aes128-scrypt.p8")
             (test-decrypt
              (pkcs8-encrypt/scrypt
               passwd key-der #:cipher '(aes cbc) #:key-size 16)
              #:openssl "^OpenSSL 1[.]1"))
    ))

