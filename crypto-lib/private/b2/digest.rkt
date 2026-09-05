;; Copyright 2018-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         brandx
         ffi/unsafe
         "../common/interfaces.rkt"
         "../common/digest.rkt"
         "../common/common.rkt"
         "ffi.rkt")
(provide b2-fetch-digest)

(define (b2-fetch-digest factory info)
  (case ($get-spec info)
    [(blake2b blake2b-512 blake2b-384 blake2b-256 blake2b-160)
     (make-digest info factory (b2b-digest-inner-impl))]
    [(blake2s blake2s-256 blake2s-224 blake2s-160 blake2s-128)
     (make-digest info factory (b2s-digest-inner-impl))]
    [else #f]))

;; ----------------------------------------

(struct b2s-digest-inner-impl ()
  #:properties
  (method-properties
   #:export ([digest-inner-impl$ #:prefix %])

   (define (%dii-digest-buffer self buf start end size)
     (define outbuf (make-bytes size))
     (blake2s outbuf (ptr-add buf start) (- end start) #f 0)
     outbuf)

   (define (%dii-new-ctx2 self di key0 config)
     (define key (or key0 #""))
     (define ic (new-blake2s-state))
     (define config-spec (get-config-spec ($get-spec di)))
     (define-values (dsize salt custom)
       (check/ref-config '(size salt custom) config config-spec #:in di))
     (define p (make-blake2s-param (or dsize ($di-size di)) (bytes-length key) salt custom))
     (blake2s_init_param ic p)
     (unless (zero? (bytes-length key))
       (define blocklen 64)
       (define keyblock (make-bytes blocklen #x00))
       (bytes-copy! keyblock 0 key 0 (bytes-length key))
       (blake2s_update ic keyblock blocklen))
     (values ic dsize))

   (define (get-config-spec dspec)
     (case dspec [(blake2s) config:blake2s+size] [else config:blake2s]))

   (define (%dii-update self ic buf start end)
     (blake2s_update ic (ptr-add buf start) (- end start)))

   (define (%dii-final self ic size)
     (define buf (make-bytes size))
     (blake2s_final ic buf)
     buf)

   (define (%dii-copy self ic)
     (define ic2 (new-blake2s-state))
     (memmove ic2 ic blake2s-state-size)
     ic2)
   ))

;; ----------------------------------------

(struct b2b-digest-inner-impl ()
  #:properties
  (method-properties
   #:export ([digest-inner-impl$ #:prefix %])

   (define (%dii-digest-buffer self buf start end size)
     (define outbuf (make-bytes size))
     (blake2b outbuf (ptr-add buf start) (- end start) #f 0)
     outbuf)

   (define (%dii-new-ctx2 self di key0 config)
     (define key (or key0 #""))
     (define ic (new-blake2b-state))
     (define config-spec (get-config-spec ($get-spec di)))
     (define-values (dsize salt custom)
       (check/ref-config '(size salt custom) config config-spec #:in di))
     (define p (make-blake2b-param (or dsize ($di-size di)) (bytes-length key) salt custom))
     (blake2b_init_param ic p)
     (unless (zero? (bytes-length key))
       (define blocklen 128)
       (define keyblock (make-bytes blocklen #x00))
       (bytes-copy! keyblock 0 key 0 (bytes-length key))
       (blake2b_update ic keyblock blocklen))
     (values ic dsize))

   (define (get-config-spec dspec)
     (case dspec [(blake2b) config:blake2b+size] [else config:blake2b]))

   (define (%dii-update self ic buf start end)
     (blake2b_update ic (ptr-add buf start) (- end start)))

   (define (%dii-final self ic size)
     (define buf (make-bytes size))
     (blake2b_final ic buf)
     buf)

   (define (%dii-copy self ic)
     (define ic2 (new-blake2b-state))
     (memmove ic2 ic blake2b-state-size)
     ic2)
   ))
