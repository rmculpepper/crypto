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
         racket/contract/base
         "interfaces.rkt"
         "catalog.rkt"
         "common.rkt"
         "digest.rkt"
         "cipher.rkt")
(provide
 (contract-out
  [private-key?
   (-> any/c boolean?)]
  [public-key?
   (-> any/c boolean?)]

  [pk-can-sign?
   (-> pk-impl? boolean?)]
  [pk-can-encrypt?
   (-> pk-impl? boolean?)]
  [public-key=?
   (->* [public-key?] [] #:rest (listof public-key?) boolean?)]
  [key->public-key
   (-> public-key? (and/c public-key? (not/c private-key?)))]

  [public-key->bytes
   (->* [public-key?] [#:format key-format/c]
        bytes?)]
  [bytes->public-key
   (->* [pk-impl? bytes?] [#:format key-format/c]
       (and/c public-key? (not/c private-key?)))]
  [private-key->bytes
   (->* [private-key?] [#:format key-format/c]
        bytes?)]
  [bytes->private-key
   (->* [pk-impl? bytes?] [#:format key-format/c]
        private-key?)]

  [pk-sign-digest
   (->* [private-key? bytes? (or/c digest-spec? digest-impl?)]
        [#:pad  sign-pad/c]
        bytes?)]
  [pk-verify-digest
   (->* [public-key? bytes? (or/c digest-spec? digest-impl?) bytes?]
        [#:pad sign-pad/c]
        boolean?)]
  [digest/sign
   (->* [private-key? (or/c digest-spec? digest-impl?) (or/c bytes? string? input-port?)]
        [#:pad sign-pad/c]
        bytes?)]
  [digest/verify
   (->* [public-key? (or/c digest-spec? digest-impl?) (or/c bytes? string? input-port?) bytes?]
        [#:pad sign-pad/c]
        boolean?)]

  [pk-encrypt
   (->* [public-key? bytes?] [#:pad encrypt-pad/c]
        bytes?)]
  [pk-decrypt
   (->* [private-key? bytes?] [#:pad encrypt-pad/c]
        bytes?)]

  ;; [encrypt-envelope
  ;;  (-> public-key? (or/c cipher-spec? cipher-impl?) (or/c bytes? string? input-port?)
  ;;      (values key/c iv/c bytes?))]
  ;; [decrypt-envelope
  ;;  (-> private-key? (or/c cipher-spec? cipher-impl?) key/c iv/c (or/c bytes? input-port?)
  ;;      bytes?)]

  [generate-pk-parameters
   (-> pk-impl? keygen-spec/c
       pk-parameters?)]
  [generate-private-key
   (-> (or/c pk-impl? pk-parameters?) keygen-spec/c
       private-key?)]))

(define nat? exact-nonnegative-integer?)
(define key/c bytes?)
(define iv/c (or/c bytes? #f))

(define encrypt-pad/c
  (or/c 'pkcs1 'oaep 'none #f))
(define sign-pad/c
  (or/c 'pkcs1 'pss 'none #f))

(define key-format/c
  (or/c #f))

;; ============================================================

(define (pk-parameters? x) (is-a? pk-params<%>))

;; A private key is really a keypair, including both private and public parts.
;; A public key contains only the public part.
(define (private-key? x)
  (and (is-a? x pk-key<%>) (send x is-private?)))
(define (public-key? x)
  (and (is-a? x pk-key<%>) #t))

(define (pk-can-sign? pki)
  (send pki can-sign?))
(define (pk-can-encrypt? pki)
  (send pki can-encrypt?))

;; Are the *public parts* of the given keys equal?
(define (public-key=? k1 . ks)
  (for/and ([k (in-list ks)])
    (send k1 equal-to-key? k)))

(define (bytes->private-key pki bs #:format [fmt #f])
  (send pki read-key 'bytes->private-key bs 'private fmt))
(define (bytes->public-key pki bs #:format [fmt #f])
  (send pki read-key 'bytes->public-key bs 'public fmt))
(define (private-key->bytes pk #:format [fmt #f])
  (send pk write-key 'private-key->bytes 'private fmt))
(define (public-key->bytes pk #:format [fmt #f])
  (send pk write-key 'public-key->bytes 'public fmt))

(define (key->public-key pk)
  (send pk get-public-key 'key->public-key))

;; ============================================================

(define (pk-sign-digest pk dbuf di #:pad [pad #f])
  (let ([di (get-spec* di)])
    (send pk sign 'pk-sign-digest dbuf di pad)))

(define (pk-verify-digest pk dbuf di sig #:pad [pad #f])
  (let ([di (get-spec* di)])
    (send pk verify 'pk-verify-digest dbuf di pad sig)))

;; ============================================================

(define (digest/sign pk di inp #:pad [pad #f])
  (let ([di (get-spec* di)])
    (send pk sign 'digest/sign (digest di inp) di pad)))

(define (digest/verify pk di inp sig #:pad [pad #f])
  (let ([di (get-spec* di)])
    (send pk verify 'digest/verify (digest di inp) di pad sig)))

;; ============================================================

(define (pk-encrypt pk buf #:pad [pad #f])
  (send pk encrypt 'pk-encrypt buf pad))

(define (pk-decrypt pk buf #:pad [pad #f])
  (send pk decrypt 'pk-decrypt buf pad))

;; ============================================================

;; ;; sk = "sealed key"
;; (define (encrypt-envelope pk ci buf)
;;   (define k (generate-cipher-key ci))
;;   (define iv (generate-cipher-iv ci))
;;   (define sk (pk-encrypt pk k))
;;   (values sk iv (encrypt ci k iv buf)))

;; (define (decrypt-envelope pk ci sk iv buf)
;;   (decrypt ci (pk-decrypt pk sk) iv buf))

;; ============================================================

(define (generate-private-key pki config)
  (send pki generate-key 'generate-private-key config))

(define (generate-pk-parameters pki config)
  (send pki generate-params 'generate-pk-parameters config))
