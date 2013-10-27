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
         "common.rkt"
         "digest.rkt"
         "cipher.rkt")
(provide
 (contract-out
  [pkey-impl?
   (-> any/c boolean?)]
  [pkey-ctx?
   (-> any/c boolean?)]
  [private-key?
   (-> pkey-ctx? boolean?)]
  [public-key?
   (-> pkey-ctx? boolean?)]
  [pkey-signature-size
   (-> pkey-ctx? nat?)]
  [pkey-bits
   (-> pkey-ctx? nat?)]
  [pkey-can-encrypt?
   (-> (or/c pkey-impl? pkey-ctx?) boolean?)]
  [public-key=?
   (->* [pkey-ctx?] [] #:rest (listof pkey-ctx?) boolean?)]
  [pkey->public-key
   (-> pkey-ctx? (and/c pkey-ctx? public-key?))]
  [public-key->bytes
   (-> pkey-ctx? bytes?)]
  [bytes->public-key
   (-> pkey-impl? bytes? (and/c pkey-ctx? public-key?))]
  [private-key->bytes
   (-> (and/c pkey-ctx? private-key?) bytes?)]
  [bytes->private-key
   (-> pkey-impl? bytes? (and/c pkey-ctx? private-key?))]

  [digest-sign
   (-> digest-ctx? pkey-ctx? bytes?)]
  [digest-verify
   (->* [digest-ctx? pkey-ctx? bytes?] [nat? nat?]
        boolean?)]
  [sign
   (-> pkey-ctx? digest-impl? (or/c bytes? input-port?)
       bytes?)]
  [verify
   (-> pkey-ctx? digest-impl? bytes? (or/c bytes? input-port?)
       boolean?)]
  [pkey-encrypt
   (->* [pkey-ctx? bytes?] [nat? nat?]
        bytes?)]
  [pkey-decrypt
   (->* [pkey-ctx? bytes?] [nat? nat?]
        bytes?)]
  [encrypt-envelope
   (-> pkey-ctx? cipher-impl? (or/c bytes? input-port?)
       (values key/c iv/c bytes?))]
  [decrypt-envelope
   (-> pkey-ctx? cipher-impl? key/c iv/c (or/c bytes? input-port?)
       bytes?)]

  [generate-pkey
   (->* (pkey-impl? nat?) () #:rest any/c
        pkey-ctx?)]))

(define nat? exact-nonnegative-integer?)
(define key/c bytes?)
(define iv/c (or/c bytes? #f))

;; ============================================================

(define (pkey-impl? x) (is-a? x pkey-impl<%>))
(define (pkey-ctx? x) (is-a? x pkey-ctx<%>))

;; A private key is really a keypair, including both private and public parts.
;; A public key contains only the public part.
(define (private-key? pk) (send pk is-private?))
(define (public-key? pk) (not (send pk is-private?)))

(define (pkey-signature-size pk) (send pk get-max-signature-size))
(define (pkey-bits pk) (send pk get-key-size/bits))

(define (pkey-can-encrypt? x)
  (cond [(is-a? x pkey-impl<%>) (send x can-encrypt?)]
        [(is-a? x pkey-ctx<%>) (send (send x get-impl) can-encrypt?)]))

;; Are the *public parts* of the given keys equal?
(define (public-key=? k1 . ks)
  (for/and ([k (in-list ks)])
    (send k1 equal-to-key? k)))

(define (bytes->private-key pki bs) (-read-pkey 'bytes->private-key pki #f bs))
(define (bytes->public-key pki bs)  (-read-pkey 'bytes->public-key pki #t bs))
(define (private-key->bytes pk) (-write-pkey 'private-key->bytes pk #f))
(define (public-key->bytes pk)  (-write-pkey 'public-key->bytes pk #t))

(define (-read-pkey who pki public? bs)
  (send pki read-key who public? bs 0 (bytes-length bs)))
(define (-write-pkey who pk public?)
  (send pk write-key who public?))

(define (pkey->public-key pk)
  (if (private-key? pk)
      (bytes->public-key (send pk get-impl) (public-key->bytes pk))
      pk))

;; ============================================================

;; pkey-sign      ;; basic sign op     = EVP_PKEY_sign
;; pkey-verify    ;; basic verify op   = EVP_PKEY_verify

;; Two APIs for signing:
;;  - (old) just create and update MD_CTX normally, call EVP_SignFinal at end
;;  - (new, since v1.0.0) create MD_CTX with EVP_DigestSignInit w/ key
;;    update normally, then call EVP_DigestSignFinal at end

;; Old API:

(define (digest-sign dg pk)
  (let* ([est-len (pkey-signature-size pk)]
         [buf (make-bytes est-len)]
         [len (send pk sign! 'digest-sign dg buf 0 est-len)])
    (shrink-bytes buf len)))

(define (digest-verify dg pk buf [start 0] [end (bytes-length buf)])
  (send pk verify 'digest-verify dg buf start end))

;; New API: TODO

;; ============================================================

(define (sign pk dgi inp)
  (cond [(bytes? inp) (-sign-bytes dgi pk inp)]
        [(string? inp) (-sign-port dgi pk (open-input-string inp))]
        [(input-port? inp) (-sign-port dgi pk inp)]))

(define (verify pk dgi inp sigbs)
  (cond [(bytes? inp) (-verify-bytes dgi pk inp sigbs)]
        [(string? inp) (-verify-port dgi pk (open-input-string inp) sigbs)]
        [(input-port? inp) (-verify-port dgi pk inp sigbs)]))

(define (-sign-bytes dgi pk bs)
  (let ([dg (make-digest-ctx dgi)])
    (digest-update dg bs)
    (digest-sign dg pk)))

(define (-sign-port dgi pk inp)
  (digest-sign (-digest-port* dgi inp) pk))

(define (-verify-bytes dgi pk bs sigbs)
  (let ([dg (make-digest-ctx dgi)])
    (digest-update dg bs)
    (digest-verify dg pk sigbs)))

(define (-verify-port dgi pk sigbs inp)
  (digest-verify (-digest-port* dgi inp) pk sigbs))

;; ============================================================

(define (pkey-encrypt pk buf)
  (send pk encrypt/decrypt 'pkey-encrypt #t #t buf 0 (bytes-length buf)))

(define (pkey-decrypt pk buf)
  (send pk encrypt/decrypt 'pkey-decrypt #f #f buf 0 (bytes-length buf)))

;; ============================================================

;; sk = "sealed key"
(define (encrypt-envelope pk ci buf)
  (define-values (k iv) (generate-cipher-key+iv ci))
  (define sk (pkey-encrypt pk k))
  (values sk iv (encrypt ci k iv buf)))

(define (decrypt-envelope pk ci sk iv buf)
  (decrypt ci (pkey-decrypt pk sk) iv buf))

;; ============================================================

(define (generate-pkey pki bits . args)
  (send pki generate-key (cons bits args)))
