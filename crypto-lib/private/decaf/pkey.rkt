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
(provide decaf-fetch-pk)

(define (decaf-fetch-pk factory info)
  (case ($get-spec info)
    [(eddsa) (decaf-eddsa-impl info factory)]
    [(ecx) (decaf-ecx-impl info factory)]
    [else #f]))

(struct keypair (param pub priv))

;; ============================================================
;; Ed25519

(struct decaf-eddsa-impl eddsa-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %]
             [curve-ok$ #:prefix %])

   (define (%curve-ok? self curve)
     (match curve
       ['ed25519 #t]
       ['ed448 #t]
       [_ #f]))

   (define (%pkp-generate-key self pkp)
     (define curve (ctx-inner pkp))
     (match curve
       ['ed25519
        (define priv (crypto-random-bytes DECAF_EDDSA_25519_PRIVATE_BYTES))
        (define pub (decaf_ed25519_derive_public_key priv))
        (pk-key self (keypair curve pub priv) #t)]
       ['ed448
        (define priv (crypto-random-bytes DECAF_EDDSA_448_PRIVATE_BYTES))
        (define pub (decaf_ed448_derive_public_key priv))
        (pk-key self (keypair curve pub priv) #t)]))

   (define (%pk-make-private-key self curve qB dB)
     (match curve
       ['ed25519
        (define priv (eddsa-check-keys curve dB qB))
        (define pub (decaf_ed25519_derive_public_key priv))
        (when qB (check-recomputed-qB pub qB))
        (pk-key self (keypair curve pub priv) #t)]
       ['ed448
        (define priv (eddsa-check-keys curve dB qB))
        (define pub (decaf_ed448_derive_public_key priv))
        (when qB (check-recomputed-qB pub qB))
        (pk-key self (keypair curve pub priv) #t)]
       [_ #f]))

   ;; ----

   (define (%pkk-sign self pkk msg _dspec _pad)
     (match-define (keypair curve pub priv) (ctx-inner pkk))
     (match curve
       ['ed25519
        (decaf_ed25519_sign priv pub msg (bytes-length msg) 0)]
       ['ed448
        (decaf_ed448_sign priv pub msg (bytes-length msg) 0)]))

   (define (%pkk-verify self pkk msg _dspec _pad sig)
     (match-define (keypair curve pub _) (ctx-inner pkk))
     (match curve
       ['ed25519
        (and (= (bytes-length sig) DECAF_EDDSA_25519_SIGNATURE_BYTES)
             (decaf_ed25519_verify sig pub msg (bytes-length msg) 0))]
       ['ed448
        (and (= (bytes-length sig) DECAF_EDDSA_448_SIGNATURE_BYTES)
             (decaf_ed448_verify sig pub msg (bytes-length msg) 0))]))
   ))

;; ============================================================
;; X25519

(struct decaf-ecx-impl ecx-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %]
             [curve-ok$ #:prefix %])

   (define (%curve-ok? self curve)
     (match curve
       ['x25519 #t]
       ['x448 #t]
       [_ #f]))

   ;; ----

   (define (%pkp-generate-key self pkp)
     (define curve ($pkp-param-values self pkp))
     (match curve
       ['x25519
        (define priv (crypto-random-bytes DECAF_X25519_PRIVATE_BYTES))
        (define pub  (decaf_x25519_derive_public_key priv))
        (pk-key self (keypair curve pub priv) #t)]
       ['x448
        (define priv (crypto-random-bytes DECAF_X448_PRIVATE_BYTES))
        (define pub  (decaf_x448_derive_public_key priv))
        (pk-key self (keypair curve pub priv) #t)]))

   (define (%pk-make-private-key self curve qB dB)
     (match curve
       ['x25519
        (define priv (ecx-check-keys curve dB qB))
        (define pub  (decaf_x25519_derive_public_key priv))
        (when qB (check-recomputed-qB pub qB))
        (pk-key self (keypair curve priv pub) #t)]
       ['x448
        (define priv (ecx-check-keys curve dB qB))
        (define pub  (decaf_x448_derive_public_key priv))
        (when qB (check-recomputed-qB pub qB))
        (pk-key self (keypair curve priv pub) #t)]
       [_ #f]))

   ;; ----

   (define (%pkk-compute-secret self pkk peer-pubkey)
     (match-define (keypair curve pub priv) (ctx-inner pkk))
     (define peer (keypair-pub (ctx-inner peer-pubkey)))
     (match curve
       ['x25519
        (or (decaf_x25519 peer priv)
            (crypto-error "operation failed" #:in pkk))]
       ['x448
        (or (decaf_x448 peer priv)
            (crypto-error "operation failed" #:in pkk))]))
   ))
