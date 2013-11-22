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
 private-key?
 public-only-key?
 (contract-out
  [pk-can-sign?
   (-> (or/c pk-impl? pk-key?) boolean?)]
  [pk-can-encrypt?
   (-> (or/c pk-impl? pk-key?) boolean?)]
  [pk-can-key-agree?
   (-> (or/c pk-impl? pk-key?) boolean?)]
  [pk-has-parameters?
   (-> (or/c pk-impl? pk-key?) boolean?)]

  [pk-key->parameters
   (-> pk-key? (or/c pk-parameters? #f))]

  [public-key=?
   (->* [pk-key?] [] #:rest (listof pk-key?) boolean?)]
  [pk-key->public-only-key
   (-> pk-key? public-only-key?)]

  [pk-key->sexpr
   (->* [pk-key?] [#:format key-format/c]
        any/c)]
  [sexpr->pk-key
   (-> pk-impl? any/c
       pk-key?)]

  [pk-parameters->sexpr
   (->* [pk-parameters?] [#:format key-format/c]
        any/c)]
  [sexpr->pk-parameters
   (-> pk-impl? any/c
       pk-parameters?)]

  [pk-sign-digest
   (->* [private-key? bytes? (or/c digest-spec? digest-impl?)]
        [#:pad  sign-pad/c]
        bytes?)]
  [pk-verify-digest
   (->* [pk-key? bytes? (or/c digest-spec? digest-impl?) bytes?]
        [#:pad sign-pad/c]
        boolean?)]
  [digest/sign
   (->* [private-key? (or/c digest-spec? digest-impl?) (or/c bytes? string? input-port?)]
        [#:pad sign-pad/c]
        bytes?)]
  [digest/verify
   (->* [pk-key? (or/c digest-spec? digest-impl?) (or/c bytes? string? input-port?) bytes?]
        [#:pad sign-pad/c]
        boolean?)]

  [pk-encrypt
   (->* [pk-key? bytes?] [#:pad encrypt-pad/c]
        bytes?)]
  [pk-decrypt
   (->* [private-key? bytes?] [#:pad encrypt-pad/c]
        bytes?)]

  ;; [encrypt-envelope
  ;;  (-> pk-key? (or/c cipher-spec? cipher-impl?) (or/c bytes? string? input-port?)
  ;;      (values key/c iv/c bytes?))]
  ;; [decrypt-envelope
  ;;  (-> private-key? (or/c cipher-spec? cipher-impl?) key/c iv/c (or/c bytes? input-port?)
  ;;      bytes?)]

  [pk-derive-secret
   (-> private-key? (or/c pk-key? bytes?)
       bytes?)]

  [generate-pk-parameters
   (->* [pk-impl?] [keygen-spec/c]
        pk-parameters?)]
  [generate-private-key
   (->* [(or/c pk-impl? pk-parameters?)] [keygen-spec/c]
        private-key?)]))

(define nat? exact-nonnegative-integer?)
(define key/c bytes?)
(define iv/c (or/c bytes? #f))

(define encrypt-pad/c
  (or/c 'pkcs1-v1.5 'oaep 'none #f))
(define sign-pad/c
  (or/c 'pkcs1-v1.5 'pss 'none #f))

(define key-format/c
  (or/c symbol? #f))

;; ============================================================

;; A private key is really a keypair, including both private and public parts.
;; A public key contains only the public part.
(define (private-key? x)
  (and (is-a? x pk-key<%>) (send x is-private?)))
(define (public-only-key? x)
  (and (is-a? x pk-key<%>) (not (send x is-private?))))

(define (pk-can-sign? pki)
  (send (get-impl* pki) can-sign?))
(define (pk-can-encrypt? pki)
  (send (get-impl* pki) can-encrypt?))
(define (pk-can-key-agree? pki)
  (send (get-impl* pki) can-key-agree?))
(define (pk-has-parameters? pki)
  (send (get-impl* pki) has-parameters?))

(define (pk-key->parameters pk)
  (and (pk-has-parameters? pk)
       (send pk get-params 'pk-key->parameters)))

;; Are the *public parts* of the given keys equal?
(define (public-key=? k1 . ks)
  (for/and ([k (in-list ks)])
    (send k1 equal-to-key? k)))

(define (pk-key->sexpr pk #:format [fmt #f])
  (send pk write-key 'pk-key->sexpr fmt))
(define (sexpr->pk-key pki sexpr)
  (send pki read-key 'sexpr->pk-key sexpr))

(define (pk-parameters->sexpr pkp #:format [fmt #f])
  (send pkp write-params 'pk-parameters->sexpr fmt))
(define (sexpr->pk-parameters pki sexpr)
  (send pki read-parameters 'sexpr->pk-parameters sexpr))

(define (pk-key->public-only-key pk)
  (send pk get-public-key 'pk-key->public-only-key))

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

(define (pk-derive-secret pk peer-key)
  (send pk compute-secret 'pk-derive-secret peer-key))

;; ============================================================

(define (generate-private-key pki config)
  (send pki generate-key 'generate-private-key config))

(define (generate-pk-parameters pki config)
  (send pki generate-params 'generate-pk-parameters config))
