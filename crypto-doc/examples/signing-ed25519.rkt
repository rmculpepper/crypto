#lang racket/base
(require racket/match crypto crypto/nettle)
(crypto-factories nettle-factory)

;; This example shows signing EdDSA with curve Ed25519.

;; Step 1: Alice generates a keypair and publishes her public key.

;; Alice:
(define alice:privkey (generate-private-key 'eddsa '((curve ed25519))))
(define alice:pubkey-spki
  (pk-key->datum alice:privkey 'SubjectPublicKeyInfo))

;; Step 2: Alice signs a message and publishes both message and signature.

;; Alice:
(define msg #"Hi, my name is Alice.")
(define sig (pk-sign alice:privkey msg))

;; Step 2: Bob obtains Alice's public key

;; Bob:
(define bob:alices-pubkey
  (datum->pk-key alice:pubkey-spki 'SubjectPublicKeyInfo))

;; Step 3: Bob verifies Alice's message

(pk-verify bob:alices-pubkey msg sig)
