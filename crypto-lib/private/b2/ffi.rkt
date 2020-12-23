;; Copyright 2018 Ryan Culpepper
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

(require (for-syntax racket/base)
         ffi/unsafe
         ffi/unsafe/define
         racket/runtime-path
         "../common/ffi.rkt")

(provide (protect-out (all-defined-out)))

;; Cooperate with `raco distribute`.
(define-runtime-path libb2-so
  '(so "libb2" ("1" #f)))

(define-values (libb2 b2-load-error)
  (ffi-lib-or-why-not libb2-so '("1" #f)))

(define-ffi-definer define-b2 libb2
  #:default-make-fail make-not-available)

(define b2-ok? (and libb2 #t))

(define BLAKE2S_BLOCKBYTES 64)
(define BLAKE2S_OUTBYTES 32)
(define BLAKE2S_KEYBYTES 32)
(define BLAKE2S_SALTBYTES 8)
(define BLAKE2S_PERSONALBYTES 8)

(define BLAKE2B_BLOCKBYTES 128)
(define BLAKE2B_OUTBYTES 64)
(define BLAKE2B_KEYBYTES 64)
(define BLAKE2B_SALTBYTES 16)
(define BLAKE2B_PERSONALBYTES 16)

(define blake2s-state-size
  (let ()
    (define-cstruct _blake2s_state
      ([h (_array _uint32 8)]
       [t (_array _uint32 2)]
       [f (_array _uint32 2)]
       [buf (_array _uint8 (* 2 BLAKE2S_BLOCKBYTES))]
       [buflen _uint32]
       [outlen _uint8]
       [last_node _uint8]))
    (ctype-sizeof _blake2s_state)))

(define blake2b-state-size
  (let ()
    (define-cstruct _blake2b_state
      ([h (_array _uint64 8)]
       [t (_array _uint64 2)]
       [f (_array _uint64 2)]
       [buf (_array _uint8 (* 2 BLAKE2B_BLOCKBYTES))]
       [buflen _uint32]
       [outlen _uint8]
       [last_node _uint8]))
    (ctype-sizeof _blake2b_state)))

(define-cpointer-type _blake2s_state)
(define-cpointer-type _blake2b_state)

(define (new-blake2s-state)
  (define ctx (malloc blake2s-state-size 'atomic-interior))
  (cpointer-push-tag! ctx blake2s_state-tag)
  ctx)

(define (new-blake2b-state)
  (define ctx (malloc blake2b-state-size 'atomic-interior))
  (cpointer-push-tag! ctx blake2b_state-tag)
  ctx)

;; ----

(define-b2 blake2s_init
  (_fun _blake2s_state _size ->  _int))
(define-b2 blake2s_init_key
  (_fun _blake2s_state _size (key : _bytes) (_size = (bytes-length key)) -> _int))
(define-b2 blake2s_update
  (_fun _blake2s_state _pointer _size -> _int))
(define-b2 blake2s_final
  (_fun _blake2s_state (buf : _bytes) (_size = (bytes-length buf)) -> _int))

(define-b2 blake2b_init
  (_fun _blake2b_state _size -> _int))
(define-b2 blake2b_init_key
  (_fun _blake2b_state _size (key : _bytes) (_size = (bytes-length key)) -> _int))
(define-b2 blake2b_update
  (_fun _blake2b_state _pointer _size -> _int))
(define-b2 blake2b_final
  (_fun _blake2b_state (buf : _bytes) (_size = (bytes-length buf)) -> _int))

(define-b2 blake2s
  (_fun (outbuf in inlen key keylen) ::
        (outbuf : _bytes)
        (in : _pointer)
        (key : _pointer)
        (_size = (bytes-length outbuf))
        (inlen : _size)
        (keylen : _size)
        -> _int))

(define-b2 blake2b
  (_fun (outbuf in inlen key keylen) ::
        (outbuf : _bytes)
        (in : _pointer)
        (key : _pointer)
        (_size = (bytes-length outbuf))
        (inlen : _size)
        (keylen : _size)
        -> _int))
