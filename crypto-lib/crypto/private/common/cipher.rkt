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
  [cipher-default-key-size
   (-> (or/c cipher-spec? cipher-impl? cipher-ctx?) nat?)]
  [cipher-key-sizes
   (-> (or/c cipher-spec? cipher-impl?) (listof nat?))]
  [cipher-block-size
   (-> (or/c cipher-spec? cipher-impl? cipher-ctx?) nat?)]
  [cipher-iv-size
   (-> (or/c cipher-spec? cipher-impl? cipher-ctx?) nat?)]
  [cipher-aead?
   (-> (or/c cipher-spec? cipher-impl? cipher-ctx?) boolean?)]
  [cipher-default-auth-size
   (-> (or/c cipher-spec? cipher-impl? cipher-ctx?) nat?)]
  [cipher-chunk-size
   (-> (or/c cipher-impl? cipher-ctx?) nat?)]

  [make-encrypt-ctx
   (->* [cipher/c key/c iv/c]
        [#:pad pad-mode/c #:auth-size (or/c nat? #f) #:auth-attached? boolean?]
        encrypt-ctx?)]
  [make-decrypt-ctx
   (->* [cipher/c key/c iv/c]
        [#:pad pad-mode/c #:auth-size (or/c nat? #f) #:auth-attached? boolean?]
        decrypt-ctx?)]
  [encrypt-ctx?
   (-> any/c boolean?)]
  [decrypt-ctx?
   (-> any/c boolean?)]
  [cipher-update
   (-> cipher-ctx? input/c bytes?)]
  [cipher-update-aad
   (-> cipher-ctx? input/c void?)]
  [cipher-final
   (->* [cipher-ctx?] [(or/c bytes? #f)] bytes?)]
  [cipher-get-auth-tag
   (-> cipher-ctx? (or/c bytes? #f))]

  [encrypt
   (->* [cipher/c key/c iv/c input/c]
        [#:pad pad-mode/c #:aad input/c #:auth-size (or/c nat? #f)
         #| #:out (or/c output-port? #f) |#]
        bytes?)]
  [decrypt
   (->* [cipher/c key/c iv/c input/c]
        [#:pad pad-mode/c #:aad input/c #:auth-size (or/c nat? #f)
         #| #:out (or/c output-port? #f) |#]
        bytes?)]

  [encrypt/auth
   (->* [cipher/c key/c iv/c input/c]
        [#:pad pad-mode/c #:aad input/c #:auth-size (or/c nat? #f)
         #| #:out (or/c output-port? #f) |#]
        (values bytes? (or/c bytes? #f)))]
  [decrypt/auth
   (->* [cipher/c key/c iv/c input/c]
        [#:pad pad-mode/c #:aad input/c #:auth-tag (or/c bytes? #f)
         #| #:out (or/c output-port? #f) |#]
        bytes?)]

  ;; encrypt-write
  ;; decrypt-write

  [generate-cipher-key
   (->* [cipher/c] [#:size nat?] key/c)]
  [generate-cipher-iv
   (->* [cipher/c] [#:size nat?] iv/c)]))

(define cipher/c (or/c cipher-spec? cipher-impl?))

(define nat? exact-nonnegative-integer?)
(define key/c bytes?)
(define iv/c (or/c bytes? #f))
(define pad-mode/c boolean?)

(define default-pad #t)

;; ----

(define (-get-impl o)
  (cond [(cipher-spec? o)
         (or (get-cipher o)
             (crypto-error "could not get cipher implementation\n  cipher: ~e" o))]
        [else (get-impl* o)]))

(define (-get-info o)
  (cond [(cipher-spec? o) (cipher-spec->info o)]
        [else (get-impl* o)]))

;; Defer to impl when avail to support unknown ciphers
;; or impl-dependent limits.

(define (cipher-default-key-size o)
  (with-crypto-entry 'cipher-default-key-size
    (send (-get-info o) get-key-size)))
(define (cipher-key-sizes o)
  (with-crypto-entry 'cipher-key-sizes
    (size-set->list (send (-get-info o) get-key-sizes))))
(define (cipher-block-size o)
  (with-crypto-entry 'cipher-block-size
    (send (-get-info o) get-block-size)))
(define (cipher-chunk-size o)
  (with-crypto-entry 'cipher-chunk-size
    (send (-get-info o) get-chunk-size)))
(define (cipher-iv-size o)
  (with-crypto-entry 'cipher-iv-size
    (send (-get-info o) get-iv-size)))
(define (cipher-aead? o)
  (with-crypto-entry 'cipher-aead?
    (send (-get-info o) aead?)))
(define (cipher-default-auth-size o)
  (with-crypto-entry 'cipher-default-auth-size
    (send (-get-info o) get-auth-size)))

;; ----

(define (encrypt-ctx? x)
  (and (cipher-ctx? x) (send x get-encrypt?)))
(define (decrypt-ctx? x)
  (and (cipher-ctx? x) (not (send x get-encrypt?))))

;; make-{en,de}crypt-ctx : ... -> cipher-ctx
;; auth-tag-size : Nat/#f -- #f means default tag size for cipher
(define (make-encrypt-ctx ci key iv #:pad [pad? #t]
                          #:auth-size [auth-size #f] #:auth-attached? [auth-attached? #t])
  (with-crypto-entry 'make-encrypt-ctx
    (-encrypt-ctx ci key iv pad? auth-size auth-attached?)))
(define (make-decrypt-ctx ci key iv #:pad [pad? #t]
                          #:auth-size [auth-size #f] #:auth-attached? [auth-attached? #t])
  (with-crypto-entry 'make-decrypt-ctx
    (-decrypt-ctx ci key iv pad? auth-size auth-attached?)))

(define (-encrypt-ctx ci key iv pad auth-size auth-attached?)
  (let ([ci (-get-impl ci)])
    (send ci new-ctx key (or iv #"") #t pad auth-size auth-attached?)))
(define (-decrypt-ctx ci key iv pad auth-size auth-attached?)
  (let ([ci (-get-impl ci)])
    (send ci new-ctx key (or iv #"") #f pad auth-size auth-attached?)))

(define (cipher-update-aad c inp)
  (with-crypto-entry 'cipher-update-aad
    (send c update-aad inp)
    (void)))

(define (cipher-update c inp)
  (with-crypto-entry 'cipher-update
    (send c update inp)
    (send c get-output)))

(define (cipher-final c [auth-tag #f])
  (with-crypto-entry 'cipher-final
    (send c final auth-tag)
    (send c get-output)))

(define (cipher-get-auth-tag c)
  (with-crypto-entry 'cipher-get-auth-tag
    (send c get-auth-tag)))

;; ----

(define (encrypt ci key iv inp
                 #:pad [pad default-pad] #:aad [aad-inp null] #:auth-size [auth-size #f])
  (with-crypto-entry 'encrypt
    (let ([ci (-get-impl ci)])
      (define ctx (-encrypt-ctx ci key iv pad auth-size #t))
      (send ctx update-aad aad-inp)
      (send ctx update inp)
      (send ctx final #f)
      (send ctx get-output))))

(define (decrypt ci key iv inp
                 #:pad [pad default-pad] #:aad [aad-inp null] #:auth-size [auth-size #f])
  (with-crypto-entry 'decrypt
    (let ([ci (-get-impl ci)])
      (define ctx (-decrypt-ctx ci key iv pad auth-size #t))
      (send ctx update-aad aad-inp)
      (send ctx update inp)
      (send ctx final #f)
      (send ctx get-output))))

(define (encrypt/auth ci key iv inp
                      #:pad [pad default-pad] #:aad [aad-inp null] #:auth-size [auth-size #f])
  (with-crypto-entry 'encrypt/auth
    (let ([ci (-get-impl ci)])
      (define ctx (-encrypt-ctx ci key iv pad auth-size #f))
      (send ctx update-aad aad-inp)
      (send ctx update inp)
      (send ctx final #f)
      (values (send ctx get-output) (send ctx get-auth-tag)))))

(define (decrypt/auth ci key iv inp
                      #:pad [pad default-pad] #:aad [aad-inp null] #:auth-tag [auth-tag #f])
  (with-crypto-entry 'decrypt
    (let ([ci (-get-impl ci)])
      (define auth-len (and auth-tag (bytes-length auth-tag)))
      (define ctx (-decrypt-ctx ci key iv pad auth-len #f))
      (send ctx update-aad aad-inp)
      (send ctx update inp)
      (send ctx final auth-tag)
      (send ctx get-output))))

;; ----

(define (generate-cipher-key ci #:size [size (cipher-default-key-size ci)])
  (with-crypto-entry 'generate-cipher-key
    ;; FIXME: any way to check for weak keys, avoid???
    (crypto-random-bytes size)))

(define (generate-cipher-iv ci #:size [size (cipher-iv-size ci)])
  (with-crypto-entry 'generate-cipher-iv
    (if (positive? size) (crypto-random-bytes size) #"")))
