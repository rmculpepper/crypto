;; Copyright 2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/class
         ffi/unsafe
         "../common/digest.rkt"
         "../common/common.rkt"
         "ffi.rkt")
(provide b2s-digest-impl%
         b2b-digest-impl%)

(define b2s-digest-impl%
  (class digest-impl%
    (inherit get-size)
    (super-new)
    (define/override (-digest-buffer inbuf instart inend size)
      (define outbuf (make-bytes size))
      (blake2s outbuf (ptr-add inbuf instart) (- inend instart) #f 0)
      outbuf)
    (define/override (-new-ctx2 key0 config)
      (define key (or key0 #""))
      (define ctx (new-blake2s-state))
      (define-values (salt custom)
        (check/ref-config '(salt custom) config config:blake2s "blake2s"))
      (define p (make-blake2s-param (get-size) (bytes-length key) salt custom))
      (blake2s_init_param ctx p)
      (unless (zero? (bytes-length key))
        (define blocklen 64)
        (define keyblock (make-bytes blocklen #x00))
        (bytes-copy! keyblock 0 key 0 (bytes-length key))
        (blake2s_update ctx keyblock blocklen))
      (new b2s-digest-ctx% (impl this) (ctx ctx)))
    ))

(define b2b-digest-impl%
  (class digest-impl%
    (inherit get-size)
    (super-new)
    (define/override (-digest-buffer inbuf instart inend size)
      (define outbuf (make-bytes size))
      (blake2b outbuf (ptr-add inbuf instart) (- inend instart) #f 0)
      outbuf)
    (define/override (-new-ctx2 key0 config)
      (define key (or key0 #""))
      (define ctx (new-blake2b-state))
      (define-values (salt custom)
        (check/ref-config '(salt custom) config config:blake2b "blake2b"))
      (define p (make-blake2b-param (get-size) (bytes-length key) salt custom))
      (blake2b_init_param ctx p)
      (unless (zero? (bytes-length key))
        (define blocklen 128)
        (define keyblock (make-bytes blocklen #x00))
        (bytes-copy! keyblock 0 key 0 (bytes-length key))
        (blake2b_update ctx keyblock blocklen))
      (new b2b-digest-ctx% (impl this) (ctx ctx)))
    ))

;; ----

(define b2s-digest-ctx%
  (class digest-ctx%
    (init-field ctx)
    (inherit-field impl)
    (super-new)
    (define/override (-update buf start end)
      (blake2s_update ctx (ptr-add buf start) (- end start)))
    (define/override (-final! buf)
      (blake2s_final ctx buf))
    (define/override (-copy)
      (define ctx2 (new-blake2s-state))
      (memmove ctx2 ctx blake2s-state-size)
      (new b2s-digest-ctx% (impl impl) (ctx ctx2)))
    ))

(define b2b-digest-ctx%
  (class digest-ctx%
    (init-field ctx)
    (inherit-field impl)
    (super-new)
    (define/override (-update buf start end)
      (blake2b_update ctx (ptr-add buf start) (- end start)))
    (define/override (-final! buf)
      (blake2b_final ctx buf))
    (define/override (-copy)
      (define ctx2 (new-blake2b-state))
      (memmove ctx2 ctx blake2b-state-size)
      (new b2b-digest-ctx% (impl impl) (ctx ctx2)))
    ))
