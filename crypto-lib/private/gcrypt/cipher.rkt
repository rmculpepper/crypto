;; Copyright 2012-2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require scramble/bundle
         scramble/struct
         ffi/unsafe
         "../common/interfaces.rkt"
         "../common/cipher.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide gcrypt-lowlevel-cipher-impl)

(struct gcrypt-lowlevel-cipher-impl
  (cipher mode aead?)
  #:properties
  (method-properties
   #:export ([lowlevel-cipher-impl$ #:prefix %])
   (define-struct-abbrevs gcrypt-lowlevel-cipher-impl)

   #;
   (define (sanity-check)
     (define key-size (gcry_cipher_get_algo_keylen cipher))
     (define chunk-size (gcry_cipher_get_algo_blklen cipher))
     __)

   (define (%llci-new-ctx self key iv enc? auth-len)
     (define ctx (gcry_cipher_open (.cipher self) (.mode self) 0))
     (gcry_cipher_setkey ctx key (bytes-length key))
     (when (positive? (bytes-length iv)) ;; (positive? iv-size)
       (if (= (.mode self) GCRY_CIPHER_MODE_CTR)
           (gcry_cipher_setctr ctx iv (bytes-length iv))
           (gcry_cipher_setiv ctx iv (bytes-length iv))))
     ctx)

   (define (%llci-aad self llc buf start end)
     (gcry_cipher_authenticate llc (ptr-add buf start) (- end start)))

   (define (%llci-crypt self llc enc? final? buf start end outbuf)
     (when final? (gcry_cipher_final llc))
     (define outlen (bytes-length outbuf))
     (if enc?
         (gcry_cipher_encrypt llc outbuf outlen (ptr-add buf start) (- end start))
         (gcry_cipher_decrypt llc outbuf outlen (ptr-add buf start) (- end start)))
     (- end start))

   (define (%llci-encrypt-end self llc auth-len)
     (cond [(positive? auth-len)
            (define tag (make-bytes auth-len))
            (gcry_cipher_gettag llc tag auth-len)
            tag]
           [else #""]))

   (define (%llci-decrypt-end self llc auth-tag)
     (when (.aead? self)
       (unless (= (gcry_cipher_checktag llc auth-tag (bytes-length auth-tag)) GPG_ERR_NO_ERROR)
         (err/auth-decrypt-failed))))

   (define (%llci-close self llc)
     (gcry_cipher_close llc))
   ))
