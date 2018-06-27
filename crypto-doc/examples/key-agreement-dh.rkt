#lang racket/base
(require racket/match crypto crypto/libcrypto)
(crypto-factories libcrypto-factory)

;; This example shows derivation of a shared secret using DH.

;; Step 0: Generate key parameters

(define params (generate-pk-parameters 'dh '((nbits 1024))))

;; Step 1: Generate private keys

;; First, Alice and Bob either generate private keys or load them from
;; storage. We'll show the case where the keys are generated fresh
;; here. The private keys are generated from the key parameters, and
;; Alice and Bob must use the same key parameters.

;; Alice:
(define alice:privkey (generate-private-key params))

;; Bob:
(define bob:privkey (generate-private-key params))

;; Step 2: Exchange public keys

;; Then they exchange their public keys using some serialization
;; format. The simplest option is to use the SubjectPublicKeyInfo
;; format.

;; Alice:
(define alice:pub-spki (pk-key->datum alice:privkey 'SubjectPublicKeyInfo))
(printf "Alice's public key (SPKI) is: ~e\n" alice:pub-spki)

;; Bob:
(define bob:pub-spki (pk-key->datum bob:privkey 'SubjectPublicKeyInfo))
(printf "Bob's public key (SPKI) is: ~e\n" bob:pub-spki)

;; Alice and Bob send each other their serialized public keys.

(define bob:alices-pub-spki alice:pub-spki)
(define alice:bobs-pub-spki bob:pub-spki)

;; Then each converts the serialized key back into a public key object.

;; Alice:
(define alice:bobs-pubkey
  (datum->pk-key alice:bobs-pub-spki 'SubjectPublicKeyInfo))

;; Bob:
(define bob:alices-pubkey
  (datum->pk-key bob:alices-pub-spki 'SubjectPublicKeyInfo))

;; Step 3: Derive shared secret

;; Finally, each party calls @racket[pk-derive-secret] with their own
;; private key and the other party's public key.

;; Alice:
(pk-derive-secret alice:privkey alice:bobs-pubkey)

;; Bob:
(pk-derive-secret bob:privkey bob:alices-pubkey)

;; Now Alice and Bob have a shared secret. They may use the shared
;; secret to, for example, derive session encryption and
;; authentication keys.
