;; Copyright 2012-2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/class
         ffi/unsafe
         "../common/digest.rkt"
         "../common/common.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide gcrypt-digest-impl%)

(define gcrypt-digest-impl%
  (class digest-impl%
    (init-field md) ;; int
    (init blocksize)
    (super-new)
    (inherit get-spec get-config-family get-size sanity-check)

    (sanity-check #:size (gcry_md_get_algo_dlen md) #:block-size blocksize)

    (define/override (-new-ctx2 key config)
      (let ([ctx (gcry_md_open md 0)])
        (case (get-config-family)
          [(cshake)
           (define-values (function custom)
             (check/ref-config '(function custom) config config:cshake "cshake"))
           (unless (and (zero? (bytes-length function)) (zero? (bytes-length custom)))
             (check-bytes 'function function 0 255 #:for "cshake" #:in this)
             (check-bytes 'custom   custom   0 255 #:for "cshake" #:in this)
             (gcry_md_cshake_customize ctx (new-cshake_customization function custom)))]
          [else
           (unless (null? config) ;; includes blake2; gcrypt does not support options
             (check-null-config config (get-spec) #:in this))])
        (when key (gcry_md_setkey ctx key (bytes-length key)))
        (new gcrypt-digest-ctx% (impl this) (ctx ctx))))

    (define/override (-new-hmac-ctx key)
      (let ([ctx (gcry_md_open md GCRY_MD_FLAG_HMAC)])
        (gcry_md_setkey ctx key (bytes-length key))
        (new gcrypt-digest-ctx% (impl this) (ctx ctx))))

    (define/override (-digest-buffer buf start end size)
      ;; FIXME: docs say "will abort the process if an unavailable algorithm is used"
      ;; so maybe not worth the trouble?
      (define outbuf (make-bytes size))
      (gcry_md_hash_buffer md outbuf (ptr-add buf start) (- end start))
      outbuf)
    ))

(define gcrypt-digest-ctx%
  (class digest-ctx%
    (init-field ctx)
    (inherit-field impl)
    (super-new)

    (define/override (-update buf start end)
      (gcry_md_write ctx (ptr-add buf start) (- end start)))

    (define/override (-final! buf)
      (gcry_md_read ctx buf (bytes-length buf))
      (gcry_md_close ctx))

    (define/override (-final-xof! buf)
      (gcry_md_extract ctx buf (bytes-length buf))
      (gcry_md_close ctx))

    (define/override (-copy)
      (let ([ctx2 (gcry_md_copy ctx)])
        (new gcrypt-digest-ctx% (impl impl) (ctx ctx2))))
    ))
