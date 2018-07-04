;; Copyright 2012-2018 Ryan Culpepper
;; Copyright 2007-2009 Dimitris Vyzovitis <vyzo at media.mit.edu>
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
         racket/match
         "interfaces.rkt"
         "common.rkt"
         "error.rkt")
(provide digest-impl%
         digest-ctx%)

;; ============================================================
;; Digest

(define digest-impl%
  (class* info-impl-base% (digest-impl<%>)
    (inherit-field info)
    (inherit get-spec)
    (super-new)

    ;; Info methods
    (define/override (about) (format "~a digest" (super about)))
    (define/public (get-size) (send info get-size))
    (define/public (get-block-size) (send info get-block-size))
    (define/public (key-size-ok? keysize) (send info key-size-ok? keysize))

    (define/public (sanity-check #:size [size #f] #:block-size [block-size #f])
      ;; Use info::get-{block-,}size directly so that subclasses can
      ;; override get-size and get-block-size.
      (when size
        (unless (= size (send info get-size))
          (internal-error "digest size: expected ~s but got ~s\n  digest: ~a"
                          (send info get-size) size (about))))
      (when block-size
        (unless (= block-size (send info get-block-size))
          (internal-error "block size: expected ~s but got ~s\n  digest: ~a"
                          (send info get-block-size) block-size (about)))))

    (define/public (new-ctx key)
      (when key (check-key-size (bytes-length key)))
      (-new-ctx key))

    (define/public (check-key-size keysize)
      (unless (key-size-ok? keysize)
        (crypto-error "bad key size\n  key: ~s bytes\n  digest: ~a"
                      keysize (about))))

    (abstract -new-ctx)       ;; Bytes/#f -> digest-ctx<%>
    (abstract new-hmac-ctx)   ;; Bytes -> digest-ctx<%>

    (define/public (digest src key)
      (define (fallback) (send (new-ctx key) digest src))
      (when key (check-key-size (bytes-length key)))
      (cond [key (fallback)]
            [else
             (match src
               [(? bytes?) (or (-digest-buffer src 0 (bytes-length src)) (fallback))]
               [(bytes-range buf start end) (or (-digest-buffer buf start end) (fallback))]
               [_ (fallback)])]))

    (define/public (hmac key src)
      (define (fallback) (send (new-hmac-ctx key) digest src))
      (match src
        [(? bytes?) (or (-hmac-buffer key src 0 (bytes-length src)) (fallback))]
        [(bytes-range buf start end) (or (-hmac-buffer key buf start end) (fallback))]
        [_ (fallback)]))

    ;; {-digest,-hmac}-buffer : ... -> Bytes/#f
    ;; Return bytes if can compute digest/hmac directly, #f to fall back
    ;; to default ctx code.
    (define/public (-digest-buffer src src-start src-end) #f)
    (define/public (-hmac-buffer key src src-start src-end) #f)
    ))

(define digest-ctx%
  (class* (state-mixin ctx-base%) (digest-ctx<%>)
    (super-new [state 'open])
    (inherit get-impl with-state)

    (define/public (digest src)
      (update src)
      (final))

    (define/public (update src)
      (with-state #:ok '(open)
        (lambda () (void (process-input src (lambda (buf start end) (-update buf start end)))))))

    (define/public (final)
      (with-state #:ok '(open) #:post 'closed
        (lambda ()
          (define dest (make-bytes (send (get-impl) get-size)))
          (-final! dest)
          dest)))

    (define/public (copy)
      (with-state #:ok '(open) (lambda () (-copy))))

    (abstract -update) ;; Bytes Nat Nat -> Void
    (abstract -final!) ;; Bytes -> Void
    (define/public (-copy) #f) ;; -> digest-ctx<%> or #f
    ))
