;; Copyright 2012-2018 Ryan Culpepper
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
         "../common/common.rkt"
         "../common/digest.rkt")
(provide rkt-hmac-ctx%)

;; Reference: http://www.ietf.org/rfc/rfc2104.txt

(define rkt-hmac-ctx%
  (class digest-ctx%
    (init-field key [ctx #f])
    (inherit-field impl)
    (super-new)

    (define block-size (send impl get-block-size))
    (define ipad (make-bytes block-size #x36))
    (define opad (make-bytes block-size #x5c))
    (when (> (bytes-length key) block-size)
      (set! key (send impl digest key #f)))
    (define (xor-with-key! pad)
      (for ([i (in-range (bytes-length key))])
        (bytes-set! pad i (bitwise-xor (bytes-ref pad i) (bytes-ref key i)))))
    (xor-with-key! ipad)
    (xor-with-key! opad)

    (unless ctx
      (set! ctx (send impl new-ctx #f))
      (send ctx update ipad))

    (define/override (-update buf start end)
      (if (and (= start 0) (= end (bytes-length buf)))
          (send ctx update buf)
          (send ctx update (bytes-range buf start end))))

    (define/override (-final! buf)
      (define mdbuf (send ctx final))
      (define ctx2 (send impl new-ctx #f))
      (send ctx2 update (list opad mdbuf))
      (bytes-copy! buf 0 (send ctx2 final)))

    (define/override (-copy)
      (new rkt-hmac-ctx% (key key) (impl impl) (ctx (send ctx copy))))
    ))
