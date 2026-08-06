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
(provide decaf-fetch-pk)

(define (decaf-fetch-pk factory info)
  (case ($get-spec info)
    [(eddsa) (decaf-eddsa-impl info factory)]
    [(ecx) (decaf-ecx-impl info factory)]
    [else #f]))

(struct keypair (param pub priv))

;; ============================================================
;; Ed25519

(struct decaf-eddsa-impl pk-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %]
             [pk*$ #:prefix %])

   (define (%pk-generate-params self config)
     (check-config config config:eddsa-keygen #:in self)
     (define curve (config-ref config 'curve))
     (or (curve->params self curve)
         (err/no-curve curve self)))

   (define (curve->params self curve)
     (and (memq curve '(ed25519 ed448))
          (pk-parameters self curve)))

   ;; ----

   (define (%pkp-generate-key self pkp)
     (define curve (ctx-inner pkp))
     (case curve
       [(ed25519)
        (define priv (crypto-random-bytes DECAF_EDDSA_25519_PRIVATE_BYTES))
        (define pub (decaf_ed25519_derive_public_key priv))
        (pk-key self (keypair curve pub priv) #t)]
       [(ed448)
        (define priv (crypto-random-bytes DECAF_EDDSA_448_PRIVATE_BYTES))
        (define pub (decaf_ed448_derive_public_key priv))
        (pk-key self (keypair curve pub priv) #t)]))

   (define (%pkp-param-values self pkp)
     (define curve-name (ctx-inner pkp))
     curve-name)

   ;; ----

   (define (%pkk-write-key self pkk fmt)
     (match-define (keypair curve pub priv) (ctx-inner pkk))
     (case curve
       [(ed25519)
        (cond [priv (encode-priv-eddsa fmt 'ed25519 pub priv)]
              [else (encode-pub-eddsa fmt 'ed25519 pub)])]
       [(ed448)
        (cond [priv (encode-priv-eddsa fmt 'ed448 pub priv)]
              [else (encode-pub-eddsa fmt 'ed448 pub)])]))


   ;; ---- pk*

   (define (%pk*-make-params self curve)
     (curve->params self curve))

   (define (%pk*-make-public-key self curve qB)
     (case curve
       [(ed25519)
        (define pub (make-sized-copy DECAF_EDDSA_25519_PUBLIC_BYTES qB))
        (pk-key self (keypair curve pub #f) #f)]
       [(ed448)
        (define pub (make-sized-copy DECAF_EDDSA_448_PUBLIC_BYTES qB))
        (pk-key self (keypair curve pub #f) #f)]
       [else #f]))

   (define (%pk*-make-private-key self curve qB dB)
     (case curve
       [(ed25519)
        (define priv (make-sized-copy DECAF_EDDSA_25519_PRIVATE_BYTES dB))
        (define pub (decaf_ed25519_derive_public_key priv))
        (when qB (check-recomputed-qB pub qB))
        (pk-key self (keypair curve pub priv) #t)]
       [(ed448)
        (define priv (make-sized-copy DECAF_EDDSA_448_PRIVATE_BYTES dB))
        (define pub (decaf_ed448_derive_public_key priv))
        (when qB (check-recomputed-qB pub qB))
        (pk-key self (keypair curve pub priv) #t)]
       [else #f]))

   ;; ----

   (define (%pkk*-sign self pkk msg _dspec _pad)
     (match-define (keypair curve pub priv) (ctx-inner pkk))
     (case curve
       [(ed25519)
        (decaf_ed25519_sign priv pub msg (bytes-length msg) 0)]
       [(ed448)
        (decaf_ed448_sign priv pub msg (bytes-length msg) 0)]
       [else (internal-error "bad curve: ~e" curve #:in pkk)]))

   (define (%pkk*-verify self pkk msg _dspec _pad sig)
     (match-define (keypair curve pub _) (ctx-inner pkk))
     (case curve
       [(ed25519)
        (and (= (bytes-length sig) DECAF_EDDSA_25519_SIGNATURE_BYTES)
             (decaf_ed25519_verify sig pub msg (bytes-length msg) 0))]
       [(ed448)
        (and (= (bytes-length sig) DECAF_EDDSA_448_SIGNATURE_BYTES)
             (decaf_ed448_verify sig pub msg (bytes-length msg) 0))]
       [else (internal-error "bad curve: ~e" curve #:in pkk)]))
   ))

;; ============================================================
;; X25519

(struct decaf-ecx-impl pk-impl-base ()
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
     (and (memq curve '(x25519 x448))
          (pk-parameters self curve)))

   ;; ----

   (define (%pkp-generate-key self pkp)
     (define curve ($pkp-param-values self pkp))
     (case curve
       [(x25519)
        (define priv (crypto-random-bytes DECAF_X25519_PRIVATE_BYTES))
        (define pub  (decaf_x25519_derive_public_key priv))
        (pk-key self (keypair curve pub priv) #t)]
       [(x448)
        (define priv (crypto-random-bytes DECAF_X448_PRIVATE_BYTES))
        (define pub  (decaf_x448_derive_public_key priv))
        (pk-key self (keypair curve pub priv) #t)]
       [else (internal-error "bad curve: ~e" curve #:in pkp)]))

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
     (curve->params self curve))

   (define (%pk*-make-public-key self curve qB)
     (case curve
       [(x25519)
        (define pub (make-sized-copy DECAF_X25519_PUBLIC_BYTES qB))
        (pk-key self (keypair curve pub #f) #f)]
       [(x448)
        (define pub (make-sized-copy DECAF_X448_PUBLIC_BYTES qB))
        (pk-key self (keypair curve pub #f) #f)]
       [else #f]))

   (define (%pk*-make-private-key self curve qB dB)
     (case curve
       [(x25519)
        (define priv (make-sized-copy DECAF_X25519_PRIVATE_BYTES dB))
        (define pub  (decaf_x25519_derive_public_key priv))
        (when qB (check-recomputed-qB pub qB))
        (pk-key self (keypair curve priv pub) #t)]
       [(x448)
        (define priv (make-sized-copy DECAF_X448_PRIVATE_BYTES dB))
        (define pub  (decaf_x448_derive_public_key priv))
        (when qB (check-recomputed-qB pub qB))
        (pk-key self (keypair curve priv pub) #t)]
       [else #f]))

   ;; ----

   (define (%pkk*-compute-secret self pkk peer-pubkey)
     (match-define (keypair curve pub priv) (ctx-inner pkk))
     (define peer (keypair-pub (ctx-inner peer-pubkey)))
     (case curve
       [(x25519)
        (or (decaf_x25519 peer priv)
            (crypto-error "operation failed" #:in pkk))]
       [(x448)
        (or (decaf_x448 peer priv)
            (crypto-error "operation failed" #:in pkk))]))

   (define (%pkk*-import-for-key-agree self pkk bs)
     (define curve (keypair-param (ctx-inner pkk)))
     ($pk*-make-public-key self curve bs))
   ))
