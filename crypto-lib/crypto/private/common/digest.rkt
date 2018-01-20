;; Copyright 2012-2014 Ryan Culpepper
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
  (with-crypto-entry 'make-digest-ctx
    (send (-get-impl di) new-ctx)))

(define (-get-impl o)
  (cond [(digest-spec? o)
         (or (get-digest o) (err/missing-digest o))]
        [else (get-impl* o)]))

(define (digest-size o)
  (with-crypto-entry 'digest-size
    (digest-spec-size (get-spec* o))))
(define (digest-block-size o)
  (with-crypto-entry 'digest-block-size
    (digest-spec-block-size (get-spec* o))))

;; ----

(define (digest-update x buf [start 0] [end (bytes-length buf)])
  (with-crypto-entry 'digest-update
    (send x update buf start end)))

(define (digest-final dg)
  (with-crypto-entry 'digest-final
    (let* ([len (digest-size dg)]
           [buf (make-bytes len)])
      (send dg final! buf 0 len)
      buf)))

(define (digest-copy dg)
  (with-crypto-entry 'digest-copy
    (send dg copy)))

(define (digest-peek-final dg)
  (with-crypto-entry 'digest-peek-final
    (let* ([dg (send dg copy)])
      (and dg
           (let* ([len (digest-size dg)]
                  [buf (make-bytes len)])
             (send dg final! buf 0 len)
             buf)))))

;; ----

(define (digest di inp)
  (with-crypto-entry 'digest
    (let ([di (-get-impl di)])
      (cond [(bytes? inp) (-digest-bytes di inp 0 (bytes-length inp))]
            [(string? inp)
             (-digest-port di (open-input-string inp))]
            [(input-port? inp) (-digest-port di inp)]))))

(define (digest-bytes di buf [start 0] [end (bytes-length buf)])
  (with-crypto-entry 'digest-bytes
    (let ([di (-get-impl di)])
      (-digest-bytes di buf start end))))

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

(define (-digest-bytes di bs start end)
  (check-input-range bs start end)
  (cond [(send di can-digest-buffer!?)
         (let ([outbuf (make-bytes (send di get-size))])
           (send di digest-buffer! bs start end outbuf 0)
           outbuf)]
        [else
         (let ([dg (make-digest-ctx di)])
           (digest-update dg bs start end)
           (digest-final dg))]))

;; ----

(define (make-hmac-ctx di key)
  (with-crypto-entry 'make-hmac-ctx
    (let* ([di (-get-impl di)]
           [himpl (send di get-hmac-impl)])
      (send himpl new-ctx key))))

(define (hmac di key inp)
  (with-crypto-entry 'hmac
    (let ([di (-get-impl di)])
      (cond [(bytes? inp) (-hmac-bytes di key inp 0 (bytes-length inp))]
            [(string? inp) (-hmac-port di key (open-input-string inp))]
            [(input-port? inp) (-hmac-port di key inp)]))))

(define (hmac-bytes di key bs [start 0] [end (bytes-length bs)])
  (with-crypto-entry 'hmac-bytes
    (let ([di (-get-impl di)])
      (-hmac-bytes di key bs start end))))

(define (-hmac-bytes di key buf start end)
  (check-input-range buf start end)
  (let ([outbuf (make-bytes (send di get-size))])
    (cond [(send di can-hmac-buffer!?)
           (send di hmac-buffer! key buf 0 (bytes-length buf) outbuf 0)]
          [else
           (let* ([himpl (send di get-hmac-impl)]
                  [hctx (send himpl new-ctx key)])
             (send hctx update buf start end)
             (send hctx final! outbuf 0 (bytes-length outbuf)))])
    outbuf))

(define (-hmac-port di key inp)
  (let* ([buf (make-bytes 4000)]
         [size (send di get-size)]
         [himpl (send di get-hmac-impl)]
         [hctx (send himpl new-ctx key)])
    (let loop ()
      (let ([count (read-bytes-avail! buf inp)])
        (cond [(eof-object? count)
               (send hctx final! buf 0 size)
               (shrink-bytes buf size)]
              [else
               (send hctx update buf 0 count)
               (loop)])))))

(define (generate-hmac-key di)
  (with-crypto-entry 'generate-hmac-key
    (crypto-random-bytes (digest-size di))))
