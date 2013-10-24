;; Copyright 2012 Ryan Culpepper
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
         "interfaces.rkt"
         "digest.rkt"
         "cipher.rkt")

;; ----

(define (!digest? x) (is-a? x digest-impl<%>))
(define (digest? x) (is-a? x digest-ctx<%>))
;; (define (!hmac? x) (is-a? x hmac-ctx<%>))

(define digest-new make-digest-ctx)
(define (-digest-ctx x) (get-field ctx x))  ;; used by pkey.rkt

(define digest->bytes digest-peek-final)

(define hmac-new make-hmac-ctx)
(define hmac-update! digest-update!)
(define hmac-final! digest-final!)
;; (define hmac? !hmac?)

;; split digest-final from digest-final!
;; split digest-peek-final from digest-peek-final!

;; ----

(define !cipher? cipher-impl?)
(define cipher? cipher-ctx?)

;; split cipher-update from cipher-update!, changed args (???)
;; cipher-final (???)

(define (cipher-encrypt ci key iv #:padding pad?)
  (make-encrypt-cipher-ctx ci key #:iv iv #:pad? pad?))
(define (cipher-decrypt ci key iv #:padding pad?)
  (make-decrypt-cipher-ctx ci key #:iv iv #:pad? pad?))

(define cipher-key-length cipher-key-size)
(define cipher-iv-length cipher-iv-size)

;; ----

(define (!pkey? x) (is-a? x pkey-impl<%>))
(define (pkey? x) (is-a? x pkey-ctx<%>))
(define (-pkey-type x) (send x get-impl))
