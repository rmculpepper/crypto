#lang racket/base
(require crypto crypto/sodium racket/match)

(crypto-factories sodium-factory)

;; In this example, Bob wants to send an encrypted message to Alice.

;; A key agreement algorithm such as X25519 can also be used to do
;; encryption. One technique for doing so is ECIES (Elliptic Curve
;; Integrated Encryption Scheme), although multiple incompatible
;; versions of ECIES have been standardized, the standards leave open
;; the choice of important parameters, and these versions predate the
;; common use of AEAD ciphers. This example is similar to (but not
;; identical to) the more recent design used by NaCl's crypto_box.


;; Step 1: Alice generates private key and publishes public key.

;; Alice:
(define alice:privkey (generate-private-key 'ecx '((curve x25519))))

;; See also key-agreement-x25519.rkt for comments on public key
;; serialization options.
(match-define (list 'ecx 'public 'x25519 alice:pub-raw)
  (pk-key->datum alice:privkey 'rkt-public))

;; Step 2: Bob receives (somehow) Alice's serialized public key and
;; deserializes it.

(define bob:alices-pub-raw alice:pub-raw)
(define bob:alices-pubkey
  (datum->pk-key `(ecx public x25519 ,bob:alices-pub-raw) 'rkt-public))

;; Step 3: Bob creates an ephemeral (single-use) private key.

(define bob:eph-privkey (generate-private-key 'ecx '((curve x25519))))
(match-define (list 'ecx 'public 'x25519 bob:eph-pub-raw)
  (pk-key->datum bob:eph-privkey 'rkt-public))

;; Step 4: Bob derives a secret from Alice's public key and his
;; ephemeral private key and creates a secret key for symmetric
;; cryptography by hashing the shared secret.

(define bob:shared-secret (pk-derive-secret bob:eph-privkey bob:alices-pubkey))
(define bob:shared-key (kdf '(hkdf sha256) bob:shared-secret #f))

;; Step 5: Bob encrypts the message using the shared key and a
;; (non-secret) nonce.

(define bob:msg #"Hello Alice, this is Bob. How are you today?")
(define bob:nonce (crypto-random-bytes 24))

(define bob:ciphertext
  (encrypt '(xchacha20-poly1305 stream) bob:shared-key bob:nonce bob:msg))

;; Step 6: Bob sends Alice his ephemeral public key, the nonce, and
;; the ciphertext.

(define bob:sealed-message (list bob:eph-pub-raw bob:nonce bob:ciphertext))
(match-define (list alice:bobs-pub-raw alice:nonce alice:ciphertext)
  bob:sealed-message)

(define alice:bobs-pubkey
  (datum->pk-key `(ecx public x25519 ,alice:bobs-pub-raw) 'rkt-public))

;; Step 7: Alice derives the secret key using her private key and
;; Bob's ephemeral public key.

(define alice:shared-secret (pk-derive-secret alice:privkey alice:bobs-pubkey))
(define alice:shared-key (kdf '(hkdf sha256) alice:shared-secret #f))

;; Step 8: Alice decrypts the message using the shared key and nonce.

(decrypt '(xchacha20-poly1305 stream) alice:shared-key alice:nonce alice:ciphertext)
