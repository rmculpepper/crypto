;; Copyright 2018-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         brandx
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/pk-common.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide (all-defined-out))

(define (sodium-fetch-pk factory info)
  (case ($get-spec info)
    [(eddsa) (sodium-eddsa-impl info factory)]
    [(ecx) (sodium-ecx-impl info factory)]
    [else #f]))

;; ============================================================
;; Ed25519

(struct sodium-eddsa-impl eddsa-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %]
             [curve-ok$ #:prefix %])
   (define-struct-abbrevs sodium-eddsa-impl)

   (define (%curve-ok? self curve)
     (match curve
       ['ed25519 #t]
       [_ #f]))

   ;; ----

   (define (%pkp-generate-key self pkp)
     (match (ctx-inner pkp)
       ['ed25519
        (define priv (make-bytes crypto_sign_ed25519_SECRETKEYBYTES))
        (define pub  (make-bytes crypto_sign_ed25519_PUBLICKEYBYTES))
        (define status (crypto_sign_ed25519_keypair pub priv))
        (unless status (crypto-error "key generation failed"))
        (pk-key self (keypair 'ed25519 pub priv) #t)]))

   (define (%pk-make-private-key self curve qB dB)
     ;; libsodium calls the secret part of the key the "seed",
     ;; and seed_keypair can be used to recompute the public key.
     (case curve
       [(ed25519)
        (define seed (eddsa-check-keys curve #t dB qB))
        (define priv (make-bytes crypto_sign_ed25519_SECRETKEYBYTES))
        (define pub (make-bytes crypto_sign_ed25519_PUBLICKEYBYTES))
        (crypto_sign_ed25519_seed_keypair pub priv seed)
        (unless (equal? seed (subbytes priv 0 32))
          (crypto-error "failed to recompute key from seed"))
        (when qB (check-recomputed-qB pub qB))
        (pk-key self (keypair curve pub priv) #t)]
       [else #f]))

   ;; ----

   (define (%pkk-sign self pkk msg _dspec _pad)
     (match-define (keypair curve pub priv) (ctx-inner pkk))
     (match curve
       ['ed25519
        (define sig (make-bytes crypto_sign_ed25519_BYTES))
        (define s (crypto_sign_ed25519_detached sig msg (bytes-length msg) priv))
        (unless s (crypto-error "failed"))
        sig]))

   (define (%pkk-verify self pkk msg _dspec _pad sig)
     (match-define (keypair curve pub _) (ctx-inner pkk))
     (match curve
       ['ed25519
        (and (= (bytes-length sig) crypto_sign_ed25519_BYTES)
             (crypto_sign_ed25519_verify_detached sig msg (bytes-length msg) pub))]))
   ))

;; ============================================================
;; X25519

(struct sodium-ecx-impl ecx-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %]
             [curve-ok$ #:prefix %])

   (define (%curve-ok? self curve)
     (match curve
       ['x25519 #t]
       [_ #f]))

   ;; ----

   (define (%pkp-generate-key self pkp)
     (define curve ($pkp-param-values self pkp))
     (match curve
       ['x25519
        (define priv (crypto-random-bytes crypto_scalarmult_curve25519_SCALARBYTES))
        (ecx-clamp-secret! 'x25519 priv)
        (define pub  (make-bytes crypto_scalarmult_curve25519_BYTES))
        (define status (crypto_scalarmult_curve25519_base pub priv))
        (unless (zero? status) (crypto-error "key generation failed"))
        (pk-key self (keypair curve pub priv) #t)]))

   (define (%pk-make-private-key self curve qB dB)
     (match curve
       ['x25519
        (define priv (ecx-check-keys curve #t dB qB))
        (define pub (make-bytes crypto_scalarmult_curve25519_BYTES))
        (crypto_scalarmult_curve25519_base pub priv)
        (when qB (check-recomputed-qB pub qB))
        (pk-key self (keypair curve pub priv) #t)]))

   ;; ----

   (define (%pkk-compute-secret self pkk peer-pubkey)
     (match-define (keypair curve pub priv) (ctx-inner pkk))
     (define peer (keypair-pub (ctx-inner peer-pubkey)))
     (match curve
       ['x25519
        (define secret (make-bytes crypto_scalarmult_curve25519_BYTES))
        (crypto_scalarmult_curve25519 secret priv peer)
        secret]))
   ))
