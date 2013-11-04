;; Copyright 2013 Ryan Culpepper
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
         "ffi.rkt")
(provide nettle-cipher-impl%)

(define (make-ctx size)
  (let ([ctx (malloc size 'atomic-interior)])
    (cpointer-push-tag! ctx CIPHER_CTX-tag)
    ctx))

(define nettle-cipher-impl%
  (class* object% (cipher-impl<%>)
    (init-field nc spec)
    (define iv-size (cipher-spec-iv-size spec))
    (super-new)

    (define/public (get-spec) spec)
    (define/public (get-block-size) (nettle-cipher-block-size nc))
    (define/public (get-iv-size) iv-size)

    (define/public (new-ctx who key iv enc? pad?)
      (check-key-size who spec (bytes-length key))
      (unless (= (if (bytes? iv) (bytes-length iv) 0) iv-size)
        (error who
               "bad IV size for cipher\n  cipher: ~e\n  expected: ~s bytes\n  got: ~s bytes"
               spec (if (bytes? iv) (bytes-length iv) 0) iv-size))
      (let* ([pad? (and pad? (cipher-spec-uses-padding? spec))]
             [ctx (new nettle-cipher-ctx% (impl this) (nc nc) (encrypt? enc?) (pad? pad?))])
        (send ctx set-key+iv key iv)
        ctx))
    ))

(define nettle-cipher-ctx%
  (class* whole-block-cipher-ctx% (cipher-ctx<%>)
    (init-field nc)
    (inherit-field impl block-size encrypt? pad?)
    (super-new)

    ;; FIXME: reconcile padding and stream ciphers (raise error?)
    (define mode (cadr (send impl get-spec)))
    (define ctx (make-ctx (nettle-cipher-context-size nc)))
    (define iv (make-bytes (send impl get-iv-size)))

    (define/public (set-key+iv key iv*)
      (when (positive? (bytes-length iv))
        (bytes-copy! iv 0 iv* 0 (bytes-length iv)))
      (if (or encrypt? (memq mode '(ctr))) ;; CTR mode uses block cipher's encrypt
          ((nettle-cipher-set-encrypt-key nc) ctx (bytes-length key) key)
          ((nettle-cipher-set-decrypt-key nc) ctx (bytes-length key) key))
      (for ([extra (in-list (nettle-cipher-extras nc))])
        (case (car extra)
          [(set-iv)
           (let ([set-iv-fun (cadr extra)])
             (set-iv-fun ctx iv))]
          [else (void)])))

    (define/override (*crypt inbuf instart inend outbuf outstart outend)
      (define crypt (if encrypt? (nettle-cipher-encrypt nc) (nettle-cipher-decrypt nc)))
      (case mode
        [(ecb stream)
         (crypt ctx (- inend instart) (ptr-add outbuf outstart) (ptr-add inbuf instart))]
        [(cbc)
         (let ([cbc_*crypt (if encrypt? nettle_cbc_encrypt nettle_cbc_decrypt)])
           (cbc_*crypt ctx crypt block-size iv (- inend instart)
                       (ptr-add outbuf outstart) (ptr-add inbuf instart)))]
        [(ctr)
         ;; Note: must use *encrypt* function in CTR mode, even when decrypting
         (let ([crypt (nettle-cipher-encrypt nc)])
           (nettle_ctr_crypt ctx crypt block-size iv (- inend instart)
                             (ptr-add outbuf outstart) (ptr-add inbuf instart)))]
        [else (error 'cipher::*crypt "internal error: bad mode: ~e\n" mode)]))

    (define/override (*crypt-partial inbuf instart inend outbuf outstart outend)
      (case mode
        [(ctr stream)
         (*crypt inbuf instart inend outbuf outstart outend)
         (- inend instart)]
        [else #f]))

    (define/override (*open?)
      (and ctx #t))

    (define/override (*close)
      (set! ctx #f)
      (set! iv #f))
    ))
