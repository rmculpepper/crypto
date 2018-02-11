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
         racket/contract/base
         "interfaces.rkt"
         "catalog.rkt"
         "factory.rkt"
         "common.rkt"
         "error.rkt")
(provide
 (contract-out
  [digest-size
   (-> (or/c digest-spec? digest-impl? digest-ctx?) exact-nonnegative-integer?)]
  [digest-block-size
   (-> (or/c digest-spec? digest-impl? digest-ctx?) exact-nonnegative-integer?)]
  [digest
   (-> digest/c input/c bytes?)]
  [hmac
   (-> digest/c bytes? input/c bytes?)]

  [make-digest-ctx
   (-> digest/c digest-ctx?)]
  [digest-update
   (-> digest-ctx? input/c void?)]
  [digest-final
   (-> digest-ctx? bytes?)]
  [digest-copy
   (-> digest-ctx? (or/c digest-ctx? #f))]
  [digest-peek-final
   (-> digest-ctx? (or/c bytes? #f))]
  [make-hmac-ctx
   (-> digest/c bytes? digest-ctx?)]
  [generate-hmac-key
   (-> digest/c bytes?)]))

(define digest/c (or/c digest-spec? digest-impl?))

;; ----

(define (make-digest-ctx di)
  (with-crypto-entry 'make-digest-ctx
    (send (-get-impl di) new-ctx)))

(define (-get-impl o)
  (cond [(digest-spec? o)
         (or (get-digest o) (err/missing-digest o))]
        [else (get-impl* o)]))

(define (-get-info o)
  (cond [(digest-spec? o) (digest-spec->info o)]
        [else (get-info* o)]))

(define (digest-size o)
  (with-crypto-entry 'digest-size
    (send (-get-info o) get-size)))
(define (digest-block-size o)
  (with-crypto-entry 'digest-block-size
    (send (-get-info o) get-block-size)))

;; ----

(define (digest-update dg src)
  (with-crypto-entry 'digest-update
    (send dg update src)))

(define (digest-final dg)
  (with-crypto-entry 'digest-final
    (send dg final)))

(define (digest-copy dg)
  (with-crypto-entry 'digest-copy
    (send dg copy)))

(define (digest-peek-final dg)
  (with-crypto-entry 'digest-peek-final
    (let ([dg2 (send dg copy)]) (and dg2 (send dg2 final)))))

;; ----

(define (digest di inp)
  (with-crypto-entry 'digest
    (let ([di (-get-impl di)])
      (send di digest inp))))

;; ----

(define (make-hmac-ctx di key)
  (with-crypto-entry 'make-hmac-ctx
    (let ([di (-get-impl di)])
      (send di new-hmac-ctx key))))

(define (hmac di key inp)
  (with-crypto-entry 'hmac
    (let ([di (-get-impl di)])
      (send di hmac key inp))))

;; ----

(define (generate-hmac-key di)
  (with-crypto-entry 'generate-hmac-key
    (crypto-random-bytes (digest-size di))))
