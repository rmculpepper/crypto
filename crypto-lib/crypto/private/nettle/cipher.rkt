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
    (inherit-field spec)
    (inherit get-iv-size)
    (super-new)

    (define chunk-size (nettle-cipher-block-size nc))
    (define/override (get-chunk-size) chunk-size)

    (define/override (new-ctx key iv enc? pad?)
      (check-key-size spec (bytes-length key))
      (check-iv-size spec (get-iv-size) iv)
      (let* ([pad? (and pad? (cipher-spec-uses-padding? spec))]
             [ctx (new nettle-cipher-ctx% (impl this) (nc nc) (encrypt? enc?) (pad? pad?))])
        (send ctx set-key+iv key iv)
        ctx))
    ))

(define nettle-cipher-ctx%
  (class* AE-whole-chunk-cipher-ctx% (cipher-ctx<%>)
    (init-field nc)
    (inherit-field impl chunk-size encrypt? pad?)
    (super-new)

    ;; FIXME: reconcile padding and stream ciphers (raise error?)
    (define mode (cipher-spec-mode (send impl get-spec)))
    (define ctx (make-ctx (nettle-cipher-context-size nc)))
    (define super-key (case mode [(gcm) (make-gcm_key)] [(eax) (make-eax_key)] [else #f]))
    (define super-ctx (case mode [(gcm) (make-gcm_ctx)] [(eax) (make-eax_ctx)] [else #f]))
    (define iv (make-bytes (send impl get-iv-size)))
    (define auth-tag #f)

    (define/public (set-key+iv key iv*)
      (when (positive? (bytes-length iv))
        (bytes-copy! iv 0 iv* 0 (bytes-length iv)))
      (if (or encrypt? (memq mode '(ctr gcm eax))) ;; CTR, GCM use block cipher's encrypt
          ((nettle-cipher-set-encrypt-key nc) ctx key)
          ((nettle-cipher-set-decrypt-key nc) ctx key))
      (case mode
        [(gcm)
         (nettle_gcm_set_key super-key ctx (nettle-cipher-encrypt nc))
         (nettle_gcm_set_iv  super-ctx super-key (bytes-length iv) iv)]
        [(eax)
         (nettle_eax_set_key super-key ctx (nettle-cipher-encrypt nc))
         (nettle_eax_set_nonce super-ctx super-key ctx (nettle-cipher-encrypt nc)
                               (bytes-length iv) iv)]
        [else (let ([set-iv (nettle-cipher-ref nc 'set-iv)])
                (when set-iv (set-iv ctx iv)))]))

    (define/override (*crypt inbuf instart inend outbuf outstart outend)
      (case mode
        [(ecb stream)
         (define crypt (if encrypt? (nettle-cipher-rkt-encrypt nc) (nettle-cipher-rkt-decrypt nc)))
         (crypt ctx (- inend instart) (ptr-add outbuf outstart) (ptr-add inbuf instart))]
        [(cbc)
         (define crypt (if encrypt? (nettle-cipher-encrypt nc) (nettle-cipher-decrypt nc)))
         (let ([cbc_*crypt (if encrypt? nettle_cbc_encrypt nettle_cbc_decrypt)])
           (cbc_*crypt ctx crypt chunk-size iv (- inend instart)
                       (ptr-add outbuf outstart) (ptr-add inbuf instart)))]
        [(ctr)
         ;; Note: must use *encrypt* function in CTR mode, even when decrypting
         (let ([crypt (nettle-cipher-encrypt nc)])
           (nettle_ctr_crypt ctx crypt chunk-size iv (- inend instart)
                             (ptr-add outbuf outstart) (ptr-add inbuf instart)))]
        [(gcm)
         ;; Note: must use *encrypt* function in GCM mode
         (let ([crypt (nettle-cipher-encrypt nc)]
               [gcm*crypt (if encrypt? nettle_gcm_encrypt nettle_gcm_decrypt)])
           (gcm*crypt super-ctx super-key ctx crypt (- inend instart)
                      (ptr-add outbuf outstart) (ptr-add inbuf instart)))]
        [(eax)
         (let ([crypt (nettle-cipher-encrypt nc)]
               [eax*crypt (if encrypt? nettle_eax_encrypt nettle_eax_decrypt)])
           (eax*crypt super-ctx super-key ctx crypt (- inend instart)
                      (ptr-add outbuf outstart) (ptr-add inbuf instart)))]
        [else (crypto-error "internal error: bad mode: ~e" mode)]))

    (define/override (*crypt-partial inbuf instart inend outbuf outstart outend)
      (case mode
        [(ctr gcm eax stream)
         (check-output-range outbuf outstart outend (- inend instart))
         (*crypt inbuf instart inend outbuf outstart outend)
         (- inend instart)]
        [else #f]))

    (define/override (*open?)
      (and ctx #t))

    (define/override (*close)
      (set! super-key #f)
      (set! super-ctx #f)
      (set! auth-tag #f)
      (set! ctx #f)
      (set! iv #f))

    (define/override (*after-final)
      (dynamic-wind void
                    (lambda ()
                      (when auth-tag
                        (define actual-AT (*get-auth-tag (bytes-length auth-tag)))
                        (unless (crypto-bytes=? auth-tag actual-AT)
                          (crypto-error "authenticated decryption failed"))))
                    (lambda () (super *after-final))))

    (define/override (*aad inbuf instart inend)
      (case mode
        [(gcm)
         (nettle_gcm_update super-ctx super-key (- inend instart) (ptr-add inbuf instart))]
        [(eax)
         (nettle_eax_update super-ctx super-key ctx (nettle-cipher-encrypt nc)
                            (- inend instart) (ptr-add inbuf instart))]
        [else
         (let ([update-aad (nettle-cipher-ref nc 'update-aad)])
           (unless update-aad (crypto-error "internal error: cannot update AAD\n  mode: ~e" mode))
           (update-aad ctx (- inend instart) (ptr-add inbuf instart)))]))

    (define/override (*set-auth-tag tag)
      (set! auth-tag tag))

    (define/override (*get-auth-tag taglen)
      (define tag (make-bytes taglen))
      (case mode
        [(gcm)
         (nettle_gcm_digest super-ctx super-key ctx (nettle-cipher-encrypt nc) taglen tag)
         tag]
        [(eax)
         (nettle_eax_digest super-ctx super-key ctx (nettle-cipher-encrypt nc) taglen tag)
         tag]
        [else
         (let ([get-auth-tag (nettle-cipher-ref nc 'get-auth-tag)])
           (unless get-auth-tag (crypto-error "internal error: cannot get auth tag\n  mode: ~e" mode))
           (get-auth-tag ctx taglen tag)
           tag)]))
    ))
