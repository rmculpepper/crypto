;; Copyright 2012 Ryan Culpepper
;; Released under the terms of the LGPL version 3 or later.
;; See the file COPYRIGHT for details.

#lang racket/base
(require racket/class
         "interfaces.rkt")
(provide base-ctx%
         shrink-bytes)

;; ----

(define base-ctx%
  (class* object% (ctx<%>)
    (init-field impl)
    (init-field [state 'ready])

    (define/public (get-impl) impl)

    (define/public (get-state) state)
    (define/public (set-state! s) (set! state s))
    (define/public (check-state! who allowed)
      (unless (memq state allowed)
        (error who "called in invalid state: ~e" state)))

    (super-new)))

;; ----

(define (shrink-bytes bs len)
  (if (< len (bytes-length bs))
    (subbytes bs 0 len)
    bs))
