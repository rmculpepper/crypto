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

    (define key-size (gcry_cipher_get_algo_keylen algo))
    (define block-size (gcry_cipher_get_algo_blklen algo))
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

    ;; Library accepts only whole blocks of text to process.
    ;; First partlen bytes of partial is waiting for rest of block.
    (define block-size (send impl get-block-size))
    (define partial (make-bytes block-size))
    (define partlen 0)

    (define/public (get-encrypt?) encrypt?)

    (define/public (update! who inbuf instart inend outbuf outstart outend)
      ;; Note: outstart is mutated
      ;; FIXME: check bounds
      ;; Split [instart,inend) into [instart,alignstart);[alignstart,alignend);[alignend,inend)
      ;; where [instart,alignstart) and [alignstart,alignend) are integral # of blocks.
      (define total0
        (+ partlen (- inend instart)))
      (define prefixlen
        (cond [(zero? partlen) 0]
              [else (min (- block-size partlen)
                         (- inend instart))]))
      (define alignstart (+ instart prefixlen))
      (define alignend0 (- inend (remainder (- inend alignstart) block-size)))
      ;; Complication: when decrypting with padding, can't output decrypted block until
      ;; first byte of next block is seen, else might miss ill-padded data.
      (define decrypting-with-pad? (and (not encrypt?) pad?))

      (define-values (alignend total)
        (cond [(and decrypting-with-pad?
                    (= alignend0 inend)
                    (< alignstart alignend))
               (values (- alignend0 block-size)
                       (- total0 block-size))]
              [else (values alignend0 total0)]))

      (bytes-copy! partial partlen inbuf instart alignstart)
      (when (and WRONG!!! (= prefixlen block-size)
                 (or (not decrypting-with-pad?)
                     (< alignstart instart)))
        (update!/aligned partial 0 block-size outbuf outstart outend)
          (set! outstart (+ outstart block-size))
          (bytes-fill! partial 0)
          (set! partlen 0)))

      (update!/aligned inbuf alignstart alignend outbuf outstart outend)
      (set! outstart (+ outstart (- alignend alignstart)))
      (when (< alignend inend)
        (bytes-copy! partial 0 inbuf alignend inend)
        (set! partlen (- inend alignend)))
      total)

    (define/private (update!/aligned inbuf instart inend outbuf outstart outend)
      (when (< instart inend)
        (let ([op (if encrypt? gcry_cipher_encrypt gcry_cipher_decrypt)])
          (op ctx
              (ptr-add outbuf outstart) (- outend outstart)
              (ptr-add inbuf instart) (- inend instart)))))

    (define/public (final! who outbuf outstart outend)
      (begin0
          (cond [pad?
                 (pad-bytes! partial partlen)
                 (gcry_cipher_encrypt ctx (ptr-add outbuf outstart) (- outend outstart)
                                      partial block-size)
                 (bytes-fill! partial 0)
                 (set! partlen 0)
                 block-size]
                [else 0])
        (gcry_cipher_close ctx)
        (set! ctx #f)))

    ;; http://en.wikipedia.org/wiki/Padding_%28cryptography%29
    (define/private (pad-bytes! buf pos)
      (pad-bytes!/pkcs7 buf pos))
    ))
