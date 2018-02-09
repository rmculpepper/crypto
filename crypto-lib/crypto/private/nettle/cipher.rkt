;; Copyright 2013-2018 Ryan Culpepper
;; 
;; This library is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as published
;; by the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;; 
;; This library is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Lesser General Public License for more details.
;; 
;; You should have received a copy of the GNU Lesser General Public License
;; along with this library.  If not, see <http://www.gnu.org/licenses/>.

#lang racket/base
(require ffi/unsafe
         racket/class
         "../common/interfaces.rkt"
         "../common/catalog.rkt"
         "../common/common.rkt"
         "../common/error.rkt"
         "../common/util.rkt"
         "ffi.rkt")
(provide nettle-cipher-impl%)

(define (make-tagged-mem size tag)
  (let ([mem (malloc size 'atomic-interior)])
    (cpointer-push-tag! mem tag)
    mem))

(define (make-ctx size) (make-tagged-mem size CIPHER_CTX-tag))
(define (make-gcm_key)  (make-tagged-mem GCM_KEY_SIZE gcm_key-tag))
(define (make-gcm_ctx)  (make-tagged-mem GCM_CTX_SIZE gcm_ctx-tag))
(define (make-eax_key) (make-tagged-mem EAX_KEY_SIZE eax_key-tag))
(define (make-eax_ctx) (make-tagged-mem EAX_CTX_SIZE eax_ctx-tag))

(define nettle-cipher-impl%
  (class* cipher-impl-base% (cipher-impl<%>)
    (init-field nc)
    (inherit get-mode sanity-check)
    (super-new)

    (define chunk-size (nettle-cipher-block-size nc))
    (define/override (get-chunk-size) chunk-size)
    (sanity-check #:chunk-size chunk-size)

    (define/override (-new-ctx key iv enc? pad? auth-len attached-tag?)
      (define ctx%
        (case (get-mode)
          [(gcm) nettle-gcm-cipher-ctx%]
          [(eax) nettle-eax-cipher-ctx%]
          [else  nettle-classic-cipher-ctx%]))
      (define ctx
        (new ctx% (impl this) (nc nc) (encrypt? enc?) (pad? pad?)
             (auth-len auth-len) (attached-tag? attached-tag?)))
      (send ctx set-key+iv key iv)
      ctx)
    ))

;; ============================================================

(define nettle-cipher-ctx-base%
  (class cipher-ctx%
    (init-field nc)
    (inherit-field impl)
    (super-new)

    (field [ctx (make-ctx (nettle-cipher-context-size nc))]
           [iv (make-bytes (send impl get-iv-size))])

    (define/public (set-key+iv key iv*)
      (when (positive? (bytes-length iv))
        (bytes-copy! iv 0 iv* 0 (bytes-length iv))))

    (define/override (-close)
      (set! ctx #f)
      (set! iv #f))

    (define/override (-do-encrypt-end auth-len)
      (-get-auth-tag auth-len))

    (define/override (-do-decrypt-end auth-tag)
      (define actual-tag (-get-auth-tag (bytes-length auth-tag)))
      (unless (crypto-bytes=? auth-tag actual-tag)
        (crypto-error "authenticated decryption failed")))

    (abstract -get-auth-tag) ;; Nat -> Bytes
    ))

(define nettle-gcm-cipher-ctx%
  (class nettle-cipher-ctx-base%
    (super-new)
    (inherit-field impl nc ctx iv)
    (inherit get-block-size get-chunk-size)

    (define gcm-key (make-gcm_key))
    (define gcm-ctx (make-gcm_ctx))

    (define/override (set-key+iv key iv*)
      (super set-key+iv key iv*)
      ;; GCM uses block cipher's encrypt
      ((nettle-cipher-set-encrypt-key nc) ctx key)
      (nettle_gcm_set_key gcm-key ctx (nettle-cipher-encrypt nc))
      (nettle_gcm_set_iv  gcm-ctx gcm-key (bytes-length iv) iv))

    (define/override (-close)
      (super -close)
      (set! gcm-key #f)
      (set! gcm-ctx #f))

    (define/override (-do-aad inbuf instart inend)
      (nettle_gcm_update gcm-ctx gcm-key (- inend instart) (ptr-add inbuf instart)))

    (define/override (-do-crypt enc? final? inbuf instart inend outbuf)
      ;; Note: must use *encrypt* function in GCM mode
      (define crypt (nettle-cipher-encrypt nc))
      (define gcm*crypt (if enc? nettle_gcm_encrypt nettle_gcm_decrypt))
      (gcm*crypt gcm-ctx gcm-key ctx crypt (- inend instart)
                 outbuf (ptr-add inbuf instart))
      (- inend instart))

    (define/override (-get-auth-tag taglen)
      (define tag (make-bytes taglen))
      (nettle_gcm_digest gcm-ctx gcm-key ctx (nettle-cipher-encrypt nc) taglen tag)
      tag)
    ))

(define nettle-eax-cipher-ctx%
  (class nettle-cipher-ctx-base%
    (super-new)
    (inherit-field impl nc ctx iv)
    (inherit get-block-size get-chunk-size)

    (define eax-key (make-eax_key))
    (define eax-ctx (make-eax_ctx))

    (define/override (set-key+iv key iv*)
      (super set-key+iv key iv*)
      ;; EAX uses block cipher's encrypt
      ((nettle-cipher-set-encrypt-key nc) ctx key)
      (nettle_eax_set_key eax-key ctx (nettle-cipher-encrypt nc))
      (nettle_eax_set_nonce eax-ctx eax-key ctx (nettle-cipher-encrypt nc)
                            (bytes-length iv) iv))

    (define/override (-close)
      (super -close)
      (set! eax-key #f)
      (set! eax-ctx #f))

    (define/override (-do-aad inbuf instart inend)
      (nettle_eax_update eax-ctx eax-key ctx (nettle-cipher-encrypt nc)
                         (- inend instart) (ptr-add inbuf instart)))

    (define/override (-do-crypt enc? final? inbuf instart inend outbuf)
      ;; Note: must use *encrypt* function in EAX mode
      (define crypt (nettle-cipher-encrypt nc))
      (define eax*crypt (if enc? nettle_eax_encrypt nettle_eax_decrypt))
      (eax*crypt eax-ctx eax-key ctx crypt (- inend instart)
                 outbuf (ptr-add inbuf instart))
      (- inend instart))

    (define/override (-get-auth-tag taglen)
      (define tag (make-bytes taglen))
      (nettle_eax_digest eax-ctx eax-key ctx (nettle-cipher-encrypt nc) taglen tag)
      tag)
    ))

(define nettle-classic-cipher-ctx%
  (class nettle-cipher-ctx-base%
    (super-new)
    (inherit-field impl nc encrypt? ctx iv)
    (inherit get-block-size get-chunk-size)

    (define/public (get-spec) (send impl get-spec))
    (define mode (send impl get-mode))

    (define/override (set-key+iv key iv*)
      (super set-key+iv key iv*)
      (if (or encrypt? (eq? mode 'ctr))
          ((nettle-cipher-set-encrypt-key nc) ctx key)
          ((nettle-cipher-set-decrypt-key nc) ctx key))
      (let ([set-iv (nettle-cipher-ref nc 'set-iv)])
        (when set-iv (set-iv ctx iv))))

    (define/override (-do-aad inbuf instart inend)
      (let ([update-aad (nettle-cipher-ref nc 'update-aad)])
        (unless update-aad
          (crypto-error "internal error: cannot update AAD\n  cipher: ~e" (get-spec)))
        (update-aad ctx (- inend instart) (ptr-add inbuf instart))))

    (define/override (-do-crypt enc? final? inbuf instart inend outbuf)
      (case mode
        [(ecb stream)
         (define crypt (if enc? (nettle-cipher-rkt-encrypt nc) (nettle-cipher-rkt-decrypt nc)))
         (crypt ctx (- inend instart) outbuf (ptr-add inbuf instart))]
        [(cbc)
         (define crypt (if enc? (nettle-cipher-encrypt nc) (nettle-cipher-decrypt nc)))
         (define cbc_*crypt (if enc? nettle_cbc_encrypt nettle_cbc_decrypt))
         (cbc_*crypt ctx crypt (get-chunk-size) iv (- inend instart)
                     outbuf (ptr-add inbuf instart))]
        [(ctr)
         ;; Note: must use *encrypt* function in CTR mode, even when decrypting
         (define crypt (nettle-cipher-encrypt nc))
         (nettle_ctr_crypt ctx crypt (get-chunk-size) iv (- inend instart)
                           outbuf (ptr-add inbuf instart))]
        [else (crypto-error "internal error: bad mode: ~e" mode)])
      (- inend instart))

    (define/override (-get-auth-tag taglen)
      (define tag (make-bytes taglen))
      (cond [(zero? taglen) (void)]
            [(nettle-cipher-ref nc 'get-auth-tag)
             => (lambda (get-auth-tag) (get-auth-tag ctx taglen tag))]
            [else (crypto-error "internal error: cannot get auth tag\n  cipher: ~s" (get-spec))])
      tag)
    ))
