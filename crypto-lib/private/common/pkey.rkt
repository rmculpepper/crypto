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
         "common.rkt"
         "digest.rkt"
         "error.rkt"
         "factory.rkt")
(provide
 private-key?
 public-only-key?
 (contract-out
  [pk-can-sign?
   (->* [(or/c pk-spec? pk-impl? pk-key?)]
        [(or/c symbol? #f) (or/c symbol? #f)]
        boolean?)]
  [pk-can-encrypt?
   (->* [(or/c pk-spec? pk-impl? pk-key?)] [(or/c symbol? #f)] boolean?)]
  [pk-can-key-agree?
   (-> (or/c pk-spec? pk-impl? pk-key?) boolean?)]
  [pk-has-parameters?
   (-> (or/c pk-spec? pk-impl? pk-key?) boolean?)]

  [pk-key->parameters
   (-> pk-key? (or/c pk-parameters? #f))]

  [public-key=?
   (->* [pk-key?] [] #:rest (listof pk-key?) boolean?)]
  [pk-key->public-only-key
   (-> pk-key? public-only-key?)]

  [pk-key->datum
   (-> pk-key? symbol? any/c)]
  [datum->pk-key
   (->* [any/c symbol?] [(or/c crypto-factory? (listof crypto-factory?))]
        pk-key?)]

  [pk-parameters->datum
   (-> pk-parameters? symbol? any/c)]
  [datum->pk-parameters
   (->* [any/c symbol?] [(or/c crypto-factory? (listof crypto-factory?))]
        pk-parameters?)]

  [pk-sign-digest
   (->* [private-key? (or/c digest-spec? digest-impl?) bytes?]
        [#:pad  sign-pad/c]
        bytes?)]
  [pk-verify-digest
   (->* [pk-key? (or/c digest-spec? digest-impl?) bytes? bytes?]
        [#:pad sign-pad/c]
        boolean?)]
  [digest/sign
   (->* [private-key? (or/c digest-spec? digest-impl?) input/c]
        [#:pad sign-pad/c]
        bytes?)]
  [digest/verify
   (->* [pk-key? (or/c digest-spec? digest-impl?) input/c bytes?]
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
   (->* [(or/c pk-spec? pk-impl?)] [config/c]
        pk-parameters?)]
  [generate-private-key
   (->* [(or/c pk-spec? pk-impl? pk-parameters?)] [config/c]
        private-key?)]))

(define nat? exact-nonnegative-integer?)
(define key/c bytes?)
(define iv/c (or/c bytes? #f))

(define encrypt-pad/c
  (or/c 'pkcs1-v1.5 'oaep 'none #f))
(define sign-pad/c
  (or/c 'pkcs1-v1.5 'pss 'pss* 'none #f))

(define key-format/c
  (or/c symbol? #f))

(define (-get-impl pki) (to-impl pki #:what "algorithm" #:lookup get-pk))

;; ============================================================

;; A private key is really a keypair, including both private and public parts.
;; A public key contains only the public part.
(define (private-key? x)
  (and (is-a? x pk-key<%>) (send x is-private?)))
(define (public-only-key? x)
  (and (is-a? x pk-key<%>) (not (send x is-private?))))

(define (pk-can-sign? pki [pad #f] [dspec #f])
  (with-crypto-entry 'pk-can-sign?
    (cond [(pk-spec? pki) (pk-spec-can-sign? pki pad)] ;; no dspec!
          [else (and (send (to-impl pki) can-sign? pad dspec) #t)])))
(define (pk-can-encrypt? pki [pad #f])
  (with-crypto-entry 'pk-can-encrypt?
    (cond [(pk-spec? pki) (pk-spec-can-encrypt? pki)]
          [else (and (send (to-impl pki) can-encrypt? pad) #t)])))
(define (pk-can-key-agree? pki)
  (with-crypto-entry 'pk-can-key-agree?
    (cond [(pk-spec? pki) (pk-spec-can-key-agree? pki)]
          [else (and (send (to-impl pki) can-key-agree?) #t)])))
(define (pk-has-parameters? pki)
  (with-crypto-entry 'pk-has-parameters?
    (cond [(pk-spec? pki) (pk-spec-has-parameters? pki)]
          [else (and (send (to-impl pki) has-params?) #t)])))

(define (pk-key->parameters pk)
  (with-crypto-entry 'pk-key->parameters
    (and (pk-has-parameters? pk)
         (send pk get-params))))

;; Are the *public parts* of the given keys equal?
(define (public-key=? k1 . ks)
  (with-crypto-entry 'public-key=?
    (for/and ([k (in-list ks)])
      (send k1 equal-to-key? k))))

(define (pk-key->datum pk fmt)
  (with-crypto-entry 'pk-key->datum
    (send pk write-key fmt)))
(define (datum->pk-key datum fmt [factory/s (crypto-factories)])
  (with-crypto-entry 'datum->pk-key
    (or (for/or ([factory (in-list (if (list? factory/s) factory/s (list factory/s)))])
          (let ([reader (send factory get-pk-reader)])
            (and reader (send reader read-key datum fmt))))
        (crypto-error "unable to read key"))))

(define (pk-parameters->datum pkp fmt)
  (with-crypto-entry 'pk-parameters->datum
    (send pkp write-params fmt)))
(define (datum->pk-parameters datum fmt [factory/s (crypto-factories)])
  (with-crypto-entry 'sexpr->pk-parameters
    (or (for/or ([factory (in-list (if (list? factory/s) factory/s (list factory/s)))])
          (let ([reader (send factory get-pk-reader)])
            (and reader (send reader read-params datum fmt))))
        (crypto-error "unable to read parameters"))))

(define (pk-key->public-only-key pk)
  (with-crypto-entry 'pk-key->public-only-key
    (send pk get-public-key)))

;; ============================================================

(define (pk-sign-digest pk di dbuf #:pad [pad #f])
  (with-crypto-entry 'pk-sign-digest
    (let ([di (to-spec di)])
      (send pk sign dbuf di pad))))

(define (pk-verify-digest pk di dbuf sig #:pad [pad #f])
  (with-crypto-entry 'pk-verify-digest
    (let ([di (to-spec di)])
      (send pk verify dbuf di pad sig))))

;; ============================================================

(define (digest/sign pk di inp #:pad [pad #f])
  (with-crypto-entry 'digest/sign
    (let* ([di (to-spec di)]
           [di* (get-digest di (get-factory pk))])
      (send pk sign (digest di* inp) di pad))))

(define (digest/verify pk di inp sig #:pad [pad #f])
  (with-crypto-entry 'digest/verify
    (let* ([di (to-spec di)]
           [di* (get-digest di (get-factory pk))])
      (send pk verify (digest di* inp) di pad sig))))

;; ============================================================

(define (pk-encrypt pk buf #:pad [pad #f])
  (with-crypto-entry 'pk-encrypt
    (send pk encrypt buf pad)))

(define (pk-decrypt pk buf #:pad [pad #f])
  (with-crypto-entry 'pk-decrypt
    (send pk decrypt buf pad)))

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
  (with-crypto-entry 'pk-derive-secret
    (send pk compute-secret peer-key)))

;; ============================================================

(define (generate-private-key pki [config '()])
  (with-crypto-entry 'generate-private-key
    (if (is-a? pki pk-params<%>)
        (send pki generate-key config)
        (let ([pki (-get-impl pki)])
          (send pki generate-key config)))))

(define (generate-pk-parameters pki [config '()])
  (with-crypto-entry 'generate-pk-parameters
    (let ([pki (-get-impl pki)])
      (send pki generate-params config))))
