;; Copyright 2014 Ryan Culpepper
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
         racket/port
         "../common/interfaces.rkt"
         "../common/catalog.rkt"
         "../common/common.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide nettle-yarrow-impl%)

(define (make-yarrow256-ctx)
  (define ctx (malloc YARROW256_CTX_SIZE 'atomic-interior))
  (cpointer-push-tag! ctx yarrow256_ctx-tag)
  ctx)

(define nettle-yarrow-impl%
  (class* impl-base% (random-impl<%>)
    (super-new)

    (field [ctx #f])

    (define/private (check-ctx [need-seeded? #t])
      (unless ctx
        (set! ctx (make-yarrow256-ctx))
        ;; FIXME: support sources?
        (nettle_yarrow256_init ctx 0 #f))
      (when need-seeded?
        (unless (nettle_yarrow256_is_seeded ctx)
          (crypto-error "nettle yarrow context not seeded"))))

    (define/public (can-add-entropy?) #t)

    (define/public (add-entropy buf entropy-in-bytes)
      (check-ctx #f)
      ;; FIXME: seed vs update?
      (nettle_yarrow256_seed ctx buf)
      (void))

    (define/public (load-file file max-bytes)
      (check-ctx #f)
      (let ([buf
             (cond [(= max-bytes +inf.0)
                    (call-with-input-file file port->bytes)]
                   [else
                    (call-with-input-file file
                      (lambda (p)
                        (read-bytes max-bytes p)))])])
        (nettle_yarrow256_seed ctx buf)))

    (define/public (rand-write-file file)
      (check-ctx #t)
      (let ([buf (make-bytes YARROW256_SEED_FILE_SIZE 0)])
        (random-bytes! buf 0 (bytes-length buf) #f)
        (call-with-output-file file
          (lambda (p)
            (write-bytes buf p)))))

    (define/public (random-bytes! buf start end _level)
      (check-output-range buf start end)
      (check-ctx #t)
      (nettle_yarrow256_random ctx (- end start) (ptr-add buf start)))

    (define/public (ok?)
      (check-ctx #f)
      (nettle_yarrow256_is_seeded ctx))
    ))
