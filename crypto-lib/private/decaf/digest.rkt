;; Copyright 2018-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         scramble/bundle
         scramble/struct
         ffi/unsafe
         "../common/interfaces.rkt"
         "../common/digest.rkt"
         "ffi.rkt")
(provide decaf-fetch-digest)

(define (decaf-fetch-digest factory info)
  (case ($get-spec info)
    [(sha512) (make-digest info factory (decaf-sha512-inner-impl))]
    [else #f]))

;; ----------------------------------------

(struct decaf-sha512-inner-impl ()
  #:properties
  (method-properties
   #:export ([digest-inner-impl$ #:prefix %])

   (define (%dii-new-ctx1 self di key)
     (define ic (new-decaf_sha512_ctx))
     (decaf_sha512_init ic)
     ic)

   (define (%dii-update self ic buf start end)
     (decaf_sha512_update ic (ptr-add buf start) (- end start)))

   (define (%dii-final self ic size)
     (define buf (make-bytes size))
     (decaf_sha512_final ic buf size)
     buf)

   (define (%dii-copy self ic)
     (define ic2 (new-decaf_sha512_ctx))
     (memmove ic2 ic (ctype-sizeof _decaf_sha512_ctx_s))
     ic2)
   ))
