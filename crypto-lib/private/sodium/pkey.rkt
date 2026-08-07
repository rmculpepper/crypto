;; Copyright 2018-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         scramble/bundle
         scramble/struct
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/pk-common.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide (all-defined-out))

(define (sodium-fetch-pk factory info)
  (case ($get-spec info)
    [(eddsa) (sodium-eddsa-impl)]
    [(ecx) (sodium-ecx-impl)]
    [else #f]))

;; ============================================================

(struct sodium-pk-impl-base pk-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %]
             [pk*$ #:prefix %])
   #:import ([pk-impl$ #:super #:prefix super-])
   (define-struct-abbrevs sodium-pk-impl-base)

   (define (%pkk-public-key self pkk)
     (match-define (pk-key impl (keypair param pub priv) private?) pkk)
     (if private? (pk-key impl (keypair param pub #f) #f) pkk))

   (define (%pkk-params self pkk)
     (cond [($pk-has-params? self)
            (define param (keypair-param (ctx-inner pkk)))
            (pk-parameters self param)]
           [else (super-pkk-params self pkk)]))
   ))

;; Size of serialized public and private key components.
(define KEYSIZE 32)

;; ============================================================
;; Ed25519

(struct sodium-eddsa-impl sodium-pk-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %]
             [pk*$ #:prefix %])
   (define-struct-abbrevs sodium-eddsa-impl)

   (define (%pk-generate-params self config)
     (check-config config config:eddsa-keygen #:in self)
     (define curve (config-ref config 'curve))
     (or (curve->params self curve)
         (err/no-curve curve self)))

   (define (curve->params self curve)
     (and (memq curve '(ed25519))
          (pk-parameters self curve)))

   ;; ----

   (define (%pkp-generate-key self pkp)
     (match (ctx-inner pkp)
       ['ed25519
        (define priv (make-bytes crypto_sign_ed25519_SECRETKEYBYTES))
        (define pub  (make-bytes crypto_sign_ed25519_PUBLICKEYBYTES))
        (define status (crypto_sign_ed25519_keypair pub priv))
        (unless status (crypto-error "key generation failed"))
        (pk-key self (keypair 'ed25519 pub priv) #t)]))

   (define (%pkp-param-values self pkp)
     (define curve-name (ctx-inner pkp))
     curve-name)

   ;; ----

   (define (%pkk-write-key self pkk fmt)
     (match-define (keypair curve pub priv) (ctx-inner pkk))
     (match curve
       ['ed25519
        (cond [priv (encode-priv-eddsa fmt 'ed25519 pub priv)]
              [else (encode-pub-eddsa fmt 'ed25519 pub)])]))

   ;; ---- pk*

   (define (%pk*-make-params self curve)
     (curve->params self curve))

   (define (%pk*-make-public-key self curve qB)
     (define (make-ed25519-public-key)
       (define pub (make-sized-copy crypto_sign_ed25519_PUBLICKEYBYTES qB))
       (pk-key self (keypair curve pub #f) #f))
     (case curve
       [(ed25519) (make-ed25519-public-key)]
       [else #f]))

   (define (%pk*-make-private-key self curve qB dB)
     ;; AFAICT, libsodium calls the secret part of the key the "seed",
     ;; and seed_keypair can be used to recompute the public key.
     (define (make-ed25519-private-key)
       (define seed (make-sized-copy crypto_sign_ed25519_SEEDBYTES dB))
       (define priv (make-bytes crypto_sign_ed25519_SECRETKEYBYTES))
       (define pub (make-bytes crypto_sign_ed25519_PUBLICKEYBYTES))
       (crypto_sign_ed25519_seed_keypair pub priv seed)
       (unless (equal? seed (subbytes priv 0 32))
         (crypto-error "failed to recompute key from seed"))
       (when qB (check-recomputed-qB pub qB))
       (pk-key self (keypair curve pub priv) #t))
     (case curve
       [(ed25519) (make-ed25519-private-key)]
       [else #f]))

   ;; ----

   (define (%pkk*-sign self pkk msg _dspec _pad)
     (match-define (keypair curve pub priv) (ctx-inner pkk))
     (match curve
       ['ed25519
        (define sig (make-bytes crypto_sign_ed25519_BYTES))
        (define s (crypto_sign_ed25519_detached sig msg (bytes-length msg) priv))
        (unless s (crypto-error "failed"))
        sig]))

   (define (%pkk*-verify self pkk msg _dspec _pad sig)
     (match-define (keypair curve pub _) (ctx-inner pkk))
     (match curve
       ['ed25519
        (and (= (bytes-length sig) crypto_sign_ed25519_BYTES)
             (crypto_sign_ed25519_verify_detached sig msg (bytes-length msg) pub))]))
   ))

;; ============================================================
;; X25519

(struct sodium-ecx-impl sodium-pk-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %]
             [pk*$ #:prefix %])

   (define (%pk-generate-params self config)
     (check-config config config:ecx-keygen #:in self)
     (define curve (config-ref config 'curve))
     (or (curve->params self curve)
         (err/no-curve curve self)))

   (define (curve->params self curve)
     (and (memq curve '(x25519))
          (pk-parameters self curve)))

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

   (define (%pkp-param-values self pkp)
     (define curve-name (ctx-inner pkp))
     curve-name)

   ;; ----

   (define (%pkk-write-key self pkk fmt)
     (match-define (keypair curve pub priv) (ctx-inner pkk))
     (cond [priv (encode-priv-ecx fmt curve pub priv)]
           [else (encode-pub-ecx fmt curve pub)]))

   ;; ---- pk*

   (define (%pk*-make-params self curve)
     (and (memq curve '(x25519))
          (curve->params self curve)))

   (define (%pk*-make-public-key self curve qB)
     (match curve
       ['x25519
        (unless (= (bytes-length qB) crypto_scalarmult_curve25519_BYTES)
          (crypto-error "invalid public key (wrong length)" #:in self))
        (define pub (make-sized-copy crypto_scalarmult_curve25519_BYTES qB))
        (pk-key self (keypair curve pub #f) #f)]))

   (define (%pk*-make-private-key self curve qB dB)
     (match curve
       ['x25519
        (define priv (make-sized-copy crypto_scalarmult_curve25519_SCALARBYTES dB))
        (define pub (make-bytes crypto_scalarmult_curve25519_BYTES))
        (crypto_scalarmult_curve25519_base pub priv)
        (when qB (check-recomputed-qB pub qB))
        (pk-key self (keypair curve priv pub) #t)]))

   ;; ----

   (define (%pkk*-compute-secret self pkk peer-pubkey)
     (match-define (keypair curve pub priv) (ctx-inner pkk))
     (define peer (keypair-pub (ctx-inner peer-pubkey)))
     (match curve
       ['x25519
        (define secret (make-bytes crypto_scalarmult_curve25519_BYTES))
        (crypto_scalarmult_curve25519 secret priv peer)
        secret]))

   (define (%pkk*-import-for-key-agree self pkk bs)
     (define curve (keypair-param (ctx-inner pkk)))
     ($pk*-make-public-key self curve bs))
   ))
