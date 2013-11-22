;; Copyright 2012-2013 Ryan Culpepper
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
         racket/contract/base
         "interfaces.rkt"
         "catalog.rkt"
         "factory.rkt"
         "common.rkt"
         "random.rkt"
         "error.rkt")
(provide
 (contract-out
  [digest-size
   (-> (or/c digest-spec? digest-impl? digest-ctx?) nat?)]
  [digest-block-size
   (-> (or/c digest-spec? digest-impl? digest-ctx?) nat?)]
  [make-digest-ctx
   (-> digest/c digest-ctx?)]
  [digest-update
   (->* [digest-ctx? bytes?] [nat? nat?]
        void?)]
  [digest-final
   (-> digest-ctx? bytes?)]
  [digest-copy
   (-> digest-ctx? (or/c digest-ctx? #f))]
  [digest-peek-final
   (-> digest-ctx? (or/c bytes? #f))]
  [digest
   (-> digest/c (or/c bytes? input-port? string?) bytes?)]
  [digest-bytes
   (->* [digest/c bytes?] [nat? nat?] bytes?)]
  [hmac
   (-> digest/c bytes? (or/c bytes? input-port? string?)
       bytes?)]
  [make-hmac-ctx
   (-> digest/c bytes? digest-ctx?)]
  [generate-hmac-key
   (-> digest/c bytes?)]))
(provide -digest-port*) ;; for pkey.rkt

(define digest/c (or/c digest-spec? digest-impl?))
(define nat? exact-nonnegative-integer?)

;; ----

(define (make-digest-ctx di)
  (send (-get-impl 'make-digest-ctx di) new-ctx))

(define (-get-impl who o)
  (cond [(digest-spec? o)
         (or (get-digest o)
             (error who "could not get digest implementation\n  digest: ~e" o))]
        [else (get-impl* o)]))

(define (digest-size o)
  (digest-spec-size (get-spec* o)))
(define (digest-block-size o)
  (digest-spec-block-size (get-spec* o)))

;; ----

(define (digest-update x buf [start 0] [end (bytes-length buf)])
  (send x update 'digest-update buf start end))

(define (digest-final dg)
  (let* ([len (digest-size dg)]
         [buf (make-bytes len)])
    (send dg final! 'digest-final buf 0 len)
    buf))

(define (digest-copy dg)
  (send dg copy 'digest-copy))

(define (digest-peek-final dg)
  (let* ([dg (send dg copy 'digest-peek-final)])
    (and dg
         (let* ([len (digest-size dg)]
                [buf (make-bytes len)])
           (send (digest-copy dg) final! 'digest-peek-final buf 0 len)
           buf))))

;; ----

(define (digest di inp)
  (let ([di (-get-impl 'digest di)])
    (cond [(bytes? inp) (-digest-bytes 'digest di inp 0 (bytes-length inp))]
          [(string? inp)
           (-digest-port di (open-input-string inp))]
          [(input-port? inp) (-digest-port di inp)])))

(define (digest-bytes di buf [start 0] [end (bytes-length buf)])
  (let ([di (-get-impl 'digest-bytes di)])
    (-digest-bytes 'digest-bytes di buf start end)))

(define (-digest-port type inp)
  (digest-final (-digest-port* type inp)))

(define (-digest-port* di inp)
  (let ([dg (make-digest-ctx di)]
        [buf (make-bytes 4000)])
    (let lp ()
      (let ([count (read-bytes-avail! buf inp)])
        (cond [(eof-object? count)
               dg]
              [else
               (digest-update dg buf 0 count)
               (lp)])))))

(define (-digest-bytes who di bs start end)
  (check-input-range who bs start end)
  (cond [(send di can-digest-buffer!?)
         (let ([outbuf (make-bytes (send di get-size))])
           (send di digest-buffer! 'digest bs start end outbuf 0)
           outbuf)]
        [else
         (let ([dg (make-digest-ctx di)])
           (digest-update dg bs start end)
           (digest-final dg))]))

;; ----

(define (make-hmac-ctx di key)
  (let* ([di (-get-impl 'make-hmac-ctx di)]
         [himpl (send di get-hmac-impl 'make-hmac-ctx)])
    (send himpl new-ctx 'make-hmac-ctx key)))

(define (hmac di key inp)
  (let ([di (-get-impl 'hmac di)])
    (cond [(bytes? inp) (-hmac-bytes 'hmac di key inp 0 (bytes-length inp))]
          [(string? inp) (-hmac-port di key (open-input-string inp))]
          [(input-port? inp) (-hmac-port di key inp)])))

(define (hmac-bytes di key bs [start 0] [end (bytes-length bs)])
  (let ([di (-get-impl 'hmac-bytes di)])
    (-hmac-bytes 'hmac-bytes di key bs start end)))

(define (-hmac-bytes who di key buf start end)
  (check-input-range who buf start end)
  (let ([outbuf (make-bytes (send di get-size))])
    (cond [(send di can-hmac-buffer!?)
           (send di hmac-buffer! 'hmac key buf 0 (bytes-length buf) outbuf 0)]
          [else
           (let* ([himpl (send di get-hmac-impl 'hmac)]
                  [hctx (send himpl new-ctx 'hmac key)])
             (send hctx update 'hmac buf start end)
             (send hctx final! 'hmac outbuf 0 (bytes-length outbuf)))])
    outbuf))

(define (-hmac-port di key inp)
  (let* ([buf (make-bytes 4000)]
         [size (send di get-size)]
         [himpl (send di get-hmac-impl 'hmac)]
         [hctx (send himpl new-ctx 'hmac key)])
    (let loop ()
      (let ([count (read-bytes-avail! buf inp)])
        (cond [(eof-object? count)
               (send hctx final! 'hmac buf 0 size)
               (shrink-bytes buf size)]
              [else
               (send hctx update 'hmac buf 0 count)
               (loop)])))))

(define (generate-hmac-key di [rand #f])
  (let ([rand (or rand (get-random* 'generate-hmac-key di))])
    (random-bytes (digest-size di) rand)))
