;; Copyright 2019 Ryan Culpepper
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
(require racket/match
         racket/contract/base
         asn1
         "main.rkt"
         "private/common/asn1.rkt"
         "private/common/error.rkt")
(provide
 (contract-out
  [pkcs8-encrypt/pbkdf2-hmac
   (->* [bytes? (or/c private-key? bytes?)]
        [#:cipher cipher-spec?
         #:digest digest-spec?
         #:iterations exact-positive-integer?
         #:key-size exact-positive-integer?]
        bytes?)]
  [pkcs8-encrypt/scrypt
   (->* [bytes? (or/c private-key? bytes?)]
        [#:cipher cipher-spec?
         #:N exact-positive-integer?
         #:r exact-positive-integer?
         #:p exact-positive-integer?
         #:key-size exact-positive-integer?]
        bytes?)]
  [pkcs8-decrypt-key
   (-> bytes? bytes? private-key?)]
  [pkcs8-decrypt-bytes
   (-> bytes? bytes? bytes?)]))

;; ------------------------------------------------------------

(define (pkcs8-encrypt/pbkdf2-hmac password privkey
                        #:cipher [cipher-alg '(aes cbc)]
                        #:digest [digest-alg 'sha512]
                        #:iterations [iters (expt 2 16)]
                        #:key-size [key-size (cipher-default-key-size cipher-alg)])
  (with-crypto-entry 'pkcs8-encrypt/pbkdf2-hmac
    (pkcs8-wrap* password
                 (pk->bytes privkey)
                 #:make-kdf (make-pbkdf2 digest-alg iters key-size)
                 #:cipher cipher-alg
                 #:key-size key-size)))

(define (pkcs8-encrypt/scrypt password privkey
                        #:cipher [cipher-alg '(aes cbc)]
                        #:N [N (expt 2 14)] #:r [r 8] #:p [p 1]
                        #:key-size [key-size (cipher-default-key-size cipher-alg)])
  (with-crypto-entry 'pkcs8-encrypt/scrypt
    (pkcs8-wrap* password
                 (pk->bytes privkey)
                 #:make-kdf (make-scrypt N r p key-size)
                 #:cipher cipher-alg
                 #:key-size key-size)))

(define (pk->bytes k)
  (if (bytes? k) k (pk-key->datum k 'OneAsymmetricKey)))

(define (pkcs8-wrap* password oak
                     #:make-kdf make-kdf
                     #:cipher cipher-alg
                     #:key-size key-size)
  (define-values (key-deriv-func make-key) (make-kdf))
  (define-values (encryption-scheme encryptor)
    (make-encryptor cipher-alg key-size))
  (define cipher-key (make-key password))
  (define encrypted-oak (encryptor cipher-key oak))
  (define pbes2-params
    (hasheq 'keyDerivationFunc key-deriv-func
            'encryptionScheme encryption-scheme))
  (define encryptionAlgorithm
    (hasheq 'algorithm id-PBES2 'parameters pbes2-params))
  (asn1->bytes/DER
   EncryptedPrivateKeyInfo
   (hasheq 'encryptionAlgorithm encryptionAlgorithm
           'encryptedData encrypted-oak)))

(define (make-pbkdf2 digest-alg iters key-size)
  (void (get-kdf `(pbkdf2 hmac ,digest-alg))) ;; for error
  (define hmac-oid
    (or (relation-ref PBKDF2-PRFs 'digest digest-alg 'oid)
        (crypto-error "unsupported PRF digest\n  digest: ~e" digest-alg)))
  (define salt (crypto-random-bytes (digest-size digest-alg)))
  (define pbkdf2-params
    (hasheq 'salt salt
            'iterationCount iters
            'keyLength key-size
            'prf (hasheq 'algorithm hmac-oid 'parameters #f)))
  (define key-deriv-func
    (hasheq 'algorithm id-PBKDF2 'parameters pbkdf2-params))
  (define (make-key password)
    (pbkdf2-hmac digest-alg password salt
                 #:iterations iters #:key-size key-size))
  (lambda () (values key-deriv-func make-key)))

(define (make-scrypt N r p key-size)
  (void (get-kdf 'scrypt)) ;; for error
  (define salt (crypto-random-bytes 16))
  (define scrypt-params
    (hasheq 'salt salt
            'costParameter N
            'blockSize r
            'parallelizationParameter p
            'keyLength key-size))
  (define key-deriv-func
    (hasheq 'algorithm id-scrypt 'parameters scrypt-params))
  (define (make-key password)
    (scrypt password salt #:N N #:r r #:p p #:key-size key-size))
  ;; Note: make-key has fixed salt, must be used only once!
  (lambda () (values key-deriv-func make-key)))

(define (make-encryptor cipher-alg key-size)
  (void (get-cipher cipher-alg)) ;; for error
  (define cipher-oid
    (or (relation-ref PBES2-Encs 'spec (list cipher-alg key-size) 'oid)
        (crypto-error "unsupported cipher\n  cipher: ~e" cipher-alg)))
  (define cipher-iv (generate-cipher-iv cipher-alg))
  (define cipher-authlen (cipher-default-auth-size cipher-alg))
  (define cipher-params
    (cond [(equal? cipher-alg '(aes gcm))
           (hasheq 'aes-nonce cipher-iv 'aes-ICVlen cipher-authlen)]
          [else cipher-iv]))
  (define encryption-scheme (hasheq 'algorithm cipher-oid 'parameters cipher-params))
  (define (encryptor cipher-key oak)
    (encrypt cipher-alg cipher-key cipher-iv oak #:auth-size cipher-authlen))
  ;; Note: encryptor has fixed IV/nonce, must be used only once!
  (values encryption-scheme encryptor))

;; ------------------------------------------------------------

(define (pkcs8-decrypt-key password p8-der)
  (with-crypto-entry 'pkcs8-decrypt-key
    (define oak-der (pkcs8-unwrap* password p8-der))
    (datum->pk-key oak-der 'OneAsymmetricKey)))

(define (pkcs8-decrypt-bytes password p8-der #:who [who 'pkcs8-unwrap-bytes])
  (with-crypto-entry 'pkcs8-decrypt-bytes
    (pkcs8-unwrap* password p8-der)))

(define (pkcs8-unwrap* password p8-der)
  (define p8 (bytes->asn1 EncryptedPrivateKeyInfo p8-der))
  (match p8
    [(hash-table ['encryptionAlgorithm
                  (hash-table ['algorithm (== id-PBES2)] ['parameters pbes2-params])]
                 ['encryptedData encrypted-oak])
     (match pbes2-params
       [(hash-table ['keyDerivationFunc keyDerivationFunc] ['encryptionScheme encryptionScheme])
        (define get-key (get-derive-key keyDerivationFunc))
        (define-values (key-size decryptor) (get-decryptor encryptionScheme))
        (define key (get-key password key-size))
        (decryptor key encrypted-oak)])]
    [(hash-table ['encryptionAlgorithm (hash-table ['algorithm alg-oid])])
     (crypto-error "unsupported PKCS #8 algorithm\n  OID: ~e" alg-oid)]))

(define (get-derive-key keyDerivationFunc)
  (match keyDerivationFunc
    [(hash-table ['algorithm (== id-PBKDF2)] ['parameters pbkdf2-params])
     (match (ensure-keys pbkdf2-params '(keyLength))
       [(hash-table ['salt salt]
                    ['iterationCount iters]
                    ['keyLength key-size1]
                    ['prf prf])
        (define prf-oid (hash-ref prf 'algorithm))
        (define digest-alg
          (or (relation-ref PBKDF2-PRFs 'oid prf-oid 'digest)
              (error 'pbkdf2->get-key "unsupported PBKDF2 PRF\n  OID: ~e" prf-oid)))
        (void (get-kdf `(pbkdf2 hmac ,digest-alg))) ;; for error
        (lambda (password key-size2)
          (pbkdf2-hmac digest-alg password salt
                       #:iterations iters #:key-size (or key-size1 key-size2)))])]
    [(hash-table ['algorithm (== id-scrypt)] ['parameters scrypt-params])
     (match (ensure-keys scrypt-params '(keyLength))
       [(hash-table ['salt salt]
                    ['costParameter N]
                    ['blockSize r]
                    ['parallelizationParameter p]
                    ['keyLength key-size1])
        (void (get-kdf 'scrypt)) ;; for error
        (lambda (password key-size2)
          (scrypt password salt #:N N #:p p #:r r #:key-size (or key-size1 key-size2)))])]
    [(hash-table ['algorithm alg])
     (error 'unwrap-pkcs8 "unsupported keyDerivationFunc\n  OID: ~e" alg)]))

(define (get-decryptor encryptionAlgorithm)
  (match encryptionAlgorithm
    [(hash-table ['algorithm cipher-oid] ['parameters cipher-param])
     (define-values (cipher-alg key-size)
       (match (relation-ref PBES2-Encs 'oid cipher-oid 'spec)
         [(list alg key-size) (values alg key-size)]
         [_ (crypto-error "unsupported encryptionAlgorithm\n  OID: ~e" cipher-oid)]))
     (define-values (iv authlen)
       (cond [(equal? cipher-alg '(aes gcm))
              (match cipher-param
                [(hash-table ['aes-nonce iv] ['aes-ICVlen authlen])
                 (values iv authlen)])]
             [else (values cipher-param #f)]))
     (void (get-cipher cipher-alg)) ;; for error
     (values key-size
             (lambda (key ciphertext)
               (with-handlers ([exn:fail? pkcs8-decrypt-error])
                 (decrypt cipher-alg key cipher-param ciphertext
                          #:auth-size authlen))))]))

(define (pkcs8-decrypt-error e)
  (crypto-error "decryption failed;\n the password may be incorrect"))
