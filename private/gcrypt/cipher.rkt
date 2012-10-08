;; Copyright 2012 Ryan Culpepper
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
(require racket/class
         ffi/unsafe
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../rkt/padding.rkt"
         "ffi.rkt")
(provide cipher-impl%)

(define cipher-impl%
  (class* object% (cipher-impl<%>)
    (init-field cipher
                mode    ;; one of 'ecb, 'cbc, 'stream (rest unsupported)
                name)
    (super-new)

    (define key-size (gcry_cipher_get_algo_keylen cipher))
    (define block-size (gcry_cipher_get_algo_blklen cipher))
    (define iv-size
      (case mode
        ((cbc) block-size)
        ((ecb) #f)
        ((stream) #f))) ;; FIXME ???

    (define/public (get-name) name)
    (define/public (get-key-size) key-size)
    (define/public (get-block-size) block-size)
    (define/public (get-iv-size) iv-size)

    (define/public (new-ctx who key iv enc? pad?)
      (let* ([mode (case mode
                     ((cbc) GCRY_CIPHER_MODE_CBC)
                     ((ecb) GCRY_CIPHER_MODE_ECB)
                     ((stream) GCRY_CIPHER_MODE_STREAM))]
             [ctx (gcry_cipher_open cipher mode 0)])
        (gcry_cipher_setkey ctx key (bytes-length key))
        (when iv-size
          (gcry_cipher_setiv ctx iv (bytes-length iv)))
        (new cipher-ctx% (impl this) (ctx ctx) (encrypt? enc?) (pad? pad?))))

    (define/public (generate-key+iv)
      (let ([key (make-bytes key-size)]
            [iv (and iv-size (make-bytes iv-size))])
        (gcry_randomize key key-size GCRY_STRONG_RANDOM)
        (and iv (gcry_randomize iv iv-size GCRY_STRONG_RANDOM))
        (values key iv)))
    ))

(define cipher-ctx%
  (class* base-ctx% (cipher-ctx<%>)
    (init-field ctx
                encrypt?
                pad?)
    (inherit-field impl)
    (super-new)

    ;; FIXME: reconcile padding and stream ciphers (raise error?)

    ;; gcrypt accepts only whole blocks.
    ;; First partlen bytes of partial is waiting for rest of block.
    (define block-size (send impl get-block-size))
    (define partial (make-bytes block-size))
    (define partlen 0)

    (define/public (get-encrypt?) encrypt?)

    (define/public (update! who inbuf instart inend outbuf outstart outend)
      (define len (- inend instart))
      (define total (+ len partlen))
      ;; First complete fill partial to *crypt separately
      ;; ... except if was empty, skip and go straight to aligned
      (define prefixlen (remainder (min len (- block-size partlen)) block-size))
      ;; Complication: when decrypting with padding, can't output decrypted block until
      ;; first byte of next block is seen, else might miss ill-padded data.
      (define flush-partial?
        (and (positive? partlen)
             (if (or encrypt? (not pad?))
                 (>= total block-size)
                 (> total block-size))))
      (define alignstart (+ instart prefixlen))
      (define alignend0 (- inend (remainder (- inend alignstart) block-size)))
      (define alignend1
        (if (or encrypt? (not pad?))
            alignend0
            (if (zero? (remainder (- alignend0 alignstart) block-size))
                (- alignend0 block-size)
                alignend0)))
      (define alignend (max alignstart alignend1))

      (define pfxoutlen (if flush-partial? block-size 0))
      (when (< instart alignstart)
        (bytes-copy! partial partlen inbuf instart alignstart))
      (cond [flush-partial?
             (*crypt partial 0 block-size outbuf outstart (+ outstart block-size)) ;; outend
             (bytes-fill! partial 0)
             (set! partlen 0)]
            [else
             (set! partlen (+ partlen prefixlen))])
      (define outstart* (+ outstart pfxoutlen))
      (define alignlen (- alignend alignstart))
      (when (< alignstart alignend)
        (*crypt inbuf alignstart alignend outbuf outstart* (+ outstart* alignlen))) ;; outend
      (when (< alignend inend) ;; implies flush-partial?
        (bytes-copy! partial 0 inbuf alignend inend)
        (set! partlen (- inend alignend)))
      (+ pfxoutlen alignlen))

    (define/private (*crypt inbuf instart inend outbuf outstart outend)
      (let ([op (if encrypt? gcry_cipher_encrypt gcry_cipher_decrypt)])
        (op ctx
            (ptr-add outbuf outstart) (- outend outstart)
            (ptr-add inbuf instart) (- inend instart))))

    (define/public (final! who outbuf outstart outend)
      (define (err/partial)
        (error who "partial block (~a)" (if encrypt? "encrypting" "decrypting")))
      (begin0
          (cond [encrypt?
                 (cond [pad?
                        (pad-bytes!/pkcs7 partial partlen)
                        (*crypt partial 0 block-size outbuf outstart outend)
                        block-size]
                       [else
                        (unless (zero? partlen)
                          ;; FIXME: better error
                          (err/partial))
                        0])]
                [else ;; decrypting
                 (cond [pad?
                        (unless (= partlen block-size)
                          (err/partial))
                        (let ([tmp (make-bytes block-size)])
                          (*crypt partial 0 block-size tmp 0 block-size)
                          (let ([pos (unpad-bytes/pkcs7 tmp)])
                            (unless pos
                              (err/partial))
                            (bytes-copy! outbuf outstart tmp 0 pos)
                            pos))]
                       [else
                        (unless (= partlen 0)
                          (err/partial))])])
        (gcry_cipher_close ctx)
        (set! ctx #f)))

    ;; http://en.wikipedia.org/wiki/Padding_%28cryptography%29
    (define/private (pad-bytes! buf pos)
      (pad-bytes!/pkcs7 buf pos))
    ))
