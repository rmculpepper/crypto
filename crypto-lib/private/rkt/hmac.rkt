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
         "../common/interfaces.rkt"
         "../common/error.rkt"
         "../common/common.rkt")
(provide rkt-hmac-impl%)

;; Reference: http://www.ietf.org/rfc/rfc2104.txt

(define rkt-hmac-impl%
  (class* impl-base% ()
    (init-field digest)
    (super-new)
    (define/public (get-digest) digest)
    (define/public (new-ctx key)
      (new rkt-hmac-ctx% (impl digest) (key key)))
    ))

(define rkt-hmac-ctx%
  (class* ctx-base% (digest-ctx<%>)
    (init-field key [ctx #f])
    (inherit-field impl)
    (super-new)

    (define block-size (send impl get-block-size))
    (define ipad (make-bytes block-size #x36))
    (define opad (make-bytes block-size #x5c))
    (let* ([key (cond [(> (bytes-length key) block-size)
                       ;; FIXME: supposed to hash the key
                       (error 'hmac "key too long")]
                      [else key])])
      (define (xor-with-key! pad)
        (for ([i (in-range (bytes-length key))])
          (bytes-set! pad i (bitwise-xor (bytes-ref pad i) (bytes-ref key i)))))
      (xor-with-key! ipad)
      (xor-with-key! opad))

    (unless ctx
      (set! ctx (send impl new-ctx))
      (send ctx update 'hmac ipad 0 block-size))

    (define/public (update buf start end)
      (send ctx update buf start end))

    (define/public (final! buf start end)
      (let* ([mdbuf (make-bytes block-size)]
             [mdlen (send ctx final! mdbuf 0 block-size)]
             [ctx2 (send impl new-ctx)])
        (send ctx2 update opad 0 block-size)
        (send ctx2 update mdbuf 0 mdlen)
        (send ctx2 final! buf start end)))

    (define/public (copy)
      (new rkt-hmac-ctx% (key key) (impl impl) (ctx (send ctx copy))))
    ))
