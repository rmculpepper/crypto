#lang racket/base
(require racket/match crypto crypto/sodium)
(crypto-factories sodium-factory)

;; This example shows derivation of a shared secret using X25519 (ECDH
;; on Curve25519).

;; Step 1: Generate private keys

;; First, Alice and Bob either generate private keys or load them from
;; storage. We'll show the case where the keys are generated fresh
;; here.

;; Alice:
(define alice:privkey (generate-private-key 'ecx '((curve x25519))))

;; Bob:
(define bob:privkey (generate-private-key 'ecx '((curve x25519))))

;; Step 2: Exchange public keys

;; Then they exchange their public keys using some serialization
;; format. For X25519, there are two good options. One is to use the
;; SubjectPublicKeyInfo format; another is to exchange the raw public
;; key bytes. Either works as each party knows how to deserialize
;; their peer's key. For the sake of demonstration, we'll have Alice
;; serialize her public key using the SubjectPublicKeyInfo format and
;; Bob serialize his key using the raw contents.

;; Alice:
;; serialized as SubjectPublicKeyInfo
(define alice:pub-spki (pk-key->datum alice:privkey 'SubjectPublicKeyInfo))
(printf "Alice's public key (SPKI) is: ~e\n" alice:pub-spki)

;; Bob:
;; raw public key (32 bytes for X25519)
(match-define (list 'ecx 'public 'x25519 bob:pub-raw)
  (pk-key->datum bob:privkey 'rkt-public))
(printf "Bob's public key (raw) is: ~e\n" bob:pub-raw)

;; Alice and Bob send each other their serialized public keys.

(define bob:alices-pub-spki alice:pub-spki)
(define alice:bobs-pub-raw bob:pub-raw)

;; Then each converts the serialized key back into a public key object.

;; Alice:
(define alice:bobs-pubkey
  (datum->pk-key `(ecx public x25519 ,alice:bobs-pub-raw) 'rkt-public))

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
