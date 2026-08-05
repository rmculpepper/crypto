;; Copyright 2012-2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require scramble/bundle
         scramble/struct
         ffi/unsafe
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/digest.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide gcrypt-digest-inner-impl)

(struct gcrypt-digest-inner-impl
  (md       ;; Int
   hmac?    ;; Boolean
   xof?     ;; Boolean
   )
  #:properties
  (method-properties
   #:export ([digest-inner-impl$ #:prefix %])
   (define-struct-abbrevs gcrypt-digest-inner-impl)

   #;
   (sanity-check #:size (gcry_md_get_algo_dlen md) #:block-size blocksize)

   (define (%dii-digest-buffer self buf start end size)
     ;; FIXME: switch to gcry_md_hash_buffers
     (cond [(.hmac? self) #f]
           [else
            (define outbuf (make-bytes size))
            (gcry_md_hash_buffer (.md self) outbuf (ptr-add buf start) (- end start))
            outbuf]))

   (define (%dii-new-ctx2 self ci key config)
     (define ic
       (cond [(.hmac? self) (gcry_md_open (.md self) GCRY_MD_FLAG_HMAC)]
             [else (gcry_md_open (.md self) 0)]))
     (case ($di-config-family ci)
       [(cshake)
        (define-values (function custom)
          (check/ref-config '(function custom) config config:cshake #:in ci))
        (unless (and (zero? (bytes-length function)) (zero? (bytes-length custom)))
          (check-bytes 'function function 0 255 #:for "cshake" #:in ci)
          (check-bytes 'custom   custom   0 255 #:for "cshake" #:in ci)
          (gcry_md_cshake_customize ic (new-cshake_customization function custom)))]
       [(blake2b blake2s)
        (unless (null? config) (check-config config null #:in ci #:impl-limit? #t))]
       [else
        (unless (null? config) (check-config config null #:in ci))])
     (when key (gcry_md_setkey ic key (bytes-length key)))
     (values ic #f))

   (define (%dii-update self ic buf start end)
     (gcry_md_write ic (ptr-add buf start) (- end start)))

   (define (%dii-final self ic size)
     (define buf (make-bytes size))
     (if (.xof? self)
         (gcry_md_extract ic buf size)
         (gcry_md_read ic buf size))
     (gcry_md_close ic)
     buf)

   (define (%dii-copy self ic)
     (gcry_md_copy ic))
   ))
