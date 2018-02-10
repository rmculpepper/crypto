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
(require racket/class
         "error.rkt"
         "../rkt/padding.rkt")
(provide (all-defined-out))

;; UFP : Update/Finish Processors

;; Notionally, a functional UFP has the type
;;
;;   type UFP in out fin res = { update : in -> out, finish fin -> (out, res) }
;;
;; One natural notion of composition is chaining, which pipes the first
;; processor's output to the second's input and the first's result to the
;; second's finish argument:
;;
;;   chain : (UFP in out fin res) -> (UFP out out' res res') -> (UFP in out' fin res')
;;
;; A useful example is a UFP that receives bytes and forwards them in chunks
;; (bytestrings whose length is a multiple of some chunk-size parameter).
;;
;;   chunkUFP  : Nat -> (UFP Bytes Chunks () Bytes)
;;
;; If we pre-compose (chain . chunkUFP), we get something like
;;   chunkUFP' : Nat -> (UFP Chunks out' Bytes res') -> (UFP Bytes out' () res')

;; A useful pattern is fin/res polymorphism (cf concatenative langs?). Compare 
;;
;;   chunkUFP' : Nat -> (UFP Chunks out' Bytes res') -> (UFP Bytes out' () res')
;;   chunkUFP* : Nat -> (UFP Chunks out' (Bytes,a) res') -> (UFP Bytes out' a res')
;;
;; The chunkUFP* version takes any finish argument type and pushes its result
;; type onto the stack, allowing more flexible composition. A useful utility for
;; this pattern is
;;
;;   pop : UFP io io (a,b) b

;; The implementation below differs from this model in two significant ways.
;;
;; 1. Most UFP classes are written in chaining style (like chunkUFP' instead of
;;    chunkUFP).
;; 2. Output is handled imperatively. A UFP's update and finish methods do not
;;    return `out` results; they pass it to the next UFP's update method. This
;;    lets them represent IO as <buf,start,end>, which reduces copying.
;;
;; But they are documented as if they were the function, uncomposed versions.

;; ============================================================
;; Design of UFPs for crypto pipelines

;; Types of processors -- naturally divide into IN/OUT and FIN/RES; discuss separately

;; IN/OUT = <bytes nat nat>, but some produce/consume additional properties. In particular:
;;   chunk : bytes => chunks  -- introduces chunkedness
;;   pad   : prop => prop     -- preserves chunkedness
;;   unpad : chunks => bytes  -- destroys chunkedness
;;   *crypt: chunks => chunks
;;
;; writing (FIN => RES)
;;                  type                     actual inst in pipelines
;;   chunk        : a => bytes,a          ;; |a| = 1
;;   add-right    : bytes/#f,a => a       ;; |a| = 0,1
;;   split-right  : a => bytes,a          ;; |a| = 0,1
;;   pad          : bytes,a => bytes,a    ;; |a| = 1
;;   unpad        : bytes,a => bytes,a    ;; |a| = 1
;;   auth-encrypt : bytes,#f,a => tag,a   ;; |a| = 0
;;   auth-decrypt : bytes,tag,a => #f,a   ;; |a| = 0
;;   update-aad   : a => a                ;; |a| = 1 -- this choice allows chunk to be monomorphic!
;;   pop          : x,a => a              ;; |a| = 0
;;   push(x)      : a => x,a              ;; |a| = 0

;; Pipelines and types
;;
;; update-aad
;;   source -> chunk -> add-right -> update-aad -> sink
;;          #f       buf,#f       #f            #f
;;
;; encrypt (detached tag) =
;;   source -> chunk -> pad  -> auth-encrypt -> sink
;;          #f       buf,#f  buf,#f          tag
;;
;; decrypt (detached tag) =
;;   source -> chunk -> auth-decrypt -> split-right -> unpad -> add-right -> sink
;;          tag      buf,tag         #f             buf,#f   buf,#f       #f
;;
;; encrypt/attached-tag =
;;   source -> chunk -> pad  -> auth-encrypt -> add-right -> push #f -> sink
;;          #f       buf,#f  buf,#f          tag          ()         #f
;;
;; decrypt/attached-tag = 
;;   source -> pop -> split-right -> chunk -> pad  -> auth-decrypt -> sink
;;          #f     ()             tag      buf,tag buf,tag         #f

;; "Optimization": since chunk and split-right occur at start of pipeline, add
;; fused update/finish to recover simplicity for case when input is single
;; bytestring.

;; ============================================================

(define ufp<%>
  (interface ()
    update
    finish
    update/finish  ;; must not have called update before!
    ))

(define sink-ufp%
  (class* object% (ufp<%>)
    (init-field update-proc finish-proc)
    (super-new)
    (define/public (update buf start end) (update-proc buf start end))
    (define/public (finish . a) (apply finish-proc a))
    (define/public (update/finish buf start end . a)
      (update buf start end)
      (send/apply this finish a))))

(define chain-ufp%
  (class* object% (ufp<%>)
    (init-field next)
    (super-new)
    (define/public (update buf [start 0] [end (bytes-length buf)])
      (send next update buf start end))
    (define/public (finish . a)
      (send/apply next finish a))
    (define/public (update/finish buf start end . a)
      (update buf start end)
      (send/apply this finish a))))

;; ----

;; chunk        : a => bytes,a          ;; |a| = 1
(define chunk-ufp%
  (class chain-ufp%
    (init-field chunk-size)
    (inherit-field next)
    (field [partial (make-bytes chunk-size)]
           [partlen 0])
    (super-new)
    (define/override (update in [instart 0] [inend (bytes-length in)])
      (when (< instart inend)
        ;; in = A+B+C; A fills partial, B chunks, C leftover
        (define inlen (- inend instart))
        (define Alen (min inlen (- chunk-size partlen)))
        (bytes-copy! partial partlen in instart (+ instart Alen))
        (cond [(= (+ partlen Alen) chunk-size)
               (send next update partial 0 chunk-size)
               (set! partlen 0)]
              [else (set! partlen (+ partlen Alen))])
        (define BClen (- inlen Alen))
        (define Bstart (+ instart Alen))
        (define Blen (- BClen (remainder BClen chunk-size))) ;; multiple of chunk-size
        (define Cstart (+ Bstart Blen))
        (unless (zero? Blen)
          (send next update in Bstart (+ Bstart Blen)))
        (bytes-copy! partial partlen in Cstart inend)
        (set! partlen (+ partlen (- inend Cstart)))))
    (define/override (finish a)
      (define res (subbytes partial 0 partlen))
      (set! partlen 0)
      (send next finish res a))
    (define/override (update/finish in instart inend a)
      (define BClen (- inend instart))
      (define Blen (- BClen (remainder BClen chunk-size)))
      (unless (zero? Blen)
        (send next update in instart (+ instart Blen)))
      (define Cstart (+ instart Blen))
      (send next finish (subbytes in Cstart inend) a))))

;; chunk1       : a => bytes,a          ;; |a| = 1
;; Chunk specialized to chunk size of 1
(define chunk1-ufp%
  (class chain-ufp%
    (inherit-field next)
    (super-new)
    (define/override (finish a)
      (send next finish #"" a))
    (define/override (update/finish in instart inend a)
      (send next update/finish in instart inend #"" a))))

;; add-right    : bytes/#f,a => a          ;; |a| = 0,1
(define add-right-ufp%
  (class chain-ufp%
    (inherit-field next)
    (super-new)
    (define/override (finish buf . a)
      (when buf (send next update buf 0 (bytes-length buf)))
      (send/apply next finish a))))

;; split-right  : a => bytes,a          ;; |a| = 0,1
(define split-right-ufp%
  (class chain-ufp%
    (init-field suffix-size)
    (inherit-field next)
    (field [partial (make-bytes suffix-size)]
           [partlen 0])
    (super-new)
    (define/override (update in [instart 0] [inend (bytes-length in)])
      (define inlen (- inend instart))
      (cond [(= instart inend) (void)]
            [(< partlen suffix-size)
             (define Alen (min inlen (- suffix-size partlen)))
             (bytes-copy! partial partlen in instart (+ instart Alen))
             (set! partlen (+ partlen Alen))
             (update in (+ instart Alen) inend)]
            [else ;; partlen = suffix-size
             ;; How much of partial gets evicted? = (total - suffix), up to suffix (length of partial)
             (define evictlen (min inlen suffix-size))
             (unless (zero? evictlen)
               (send next update partial 0 evictlen)
               (bytes-copy! partial 0 partial evictlen suffix-size))
             ;; How much of in gets sent?
             ;; = (inlen - evictlen) = (inlen - min(inlen, suffix)) = max(0, inlen - suffix)
             (define sendlen (- inlen evictlen))
             (unless (zero? sendlen)
               (send next update in instart (+ instart sendlen)))
             (bytes-copy! partial (- suffix-size evictlen) in (+ instart sendlen) inend)]))
    (define/override (finish . a)
      (define r (subbytes partial 0 partlen))
      (set! partlen 0)
      (send/apply next finish r a))
    (define/override (update/finish in instart inend . a)
      (define inlen (- inend instart))
      (define ulen (max 0 (- inlen suffix-size)))
      (send/apply next update/finish in instart (+ instart ulen)
                  (subbytes (+ instart ulen) inend) a))))

;; pad          : bytes,a => bytes,a    ;; |a| = 1
;; Add PKCS7 padding
;; FIXME: fix case when block-size != chunk-size
(define pad-ufp%
  (class chain-ufp%
    (init-field block-size)
    (inherit-field next)
    (super-new)
    (define/override (finish buf a)
      ;; Note: if buf is whole block, pads to 2 whole blocks.. problem?
      (send next finish (pad-bytes/pkcs7 buf block-size) a))))

;; unpad        : bytes,a => bytes,a    ;; |a| = 1
;; Check and remove PKCS7 padding
(define unpad-ufp%
  (class chain-ufp%
    (inherit-field next)
    (super-new)
    (define/override (finish buf a)
      (send next finish (unpad-bytes/pkcs7 buf) a))))

;; pop          : x,a => a              ;; |a| = 0
(define pop-ufp%
  (class chain-ufp%
    (inherit-field next)
    (super-new)
    (define/override (finish v)
      (send next finish))
    (define/override (update/finish buf start end v)
      (send next update/finish buf start end))))

;; push(x)      : a => x,a              ;; |a| = 0
(define push-ufp%
  (class chain-ufp%
    (init-field value)
    (inherit-field next)
    (super-new)
    (define/override (finish)
      (send next finish value))))

;;   auth-encrypt : bytes,#f,a => tag,a   ;; |a| = 0
;;   auth-decrypt : bytes,tag,a => #f,a   ;; |a| = 0
;;   update-aad   : a => a                ;; |a| = 1 -- this choice allows chunk to be monomorphic!

;; ------------------------------------------------------------

(define (sink-ufp update-proc finish-proc)
  (new sink-ufp% (update-proc update-proc) (finish-proc finish-proc)))
(define (chunk-ufp chunk-size next)
  (if (= chunk-size 1)
      (new chunk1-ufp% (next next))
      (new chunk-ufp% (chunk-size chunk-size) (next next))))
(define (add-right-ufp next)
  (new add-right-ufp% (next next)))
(define (split-right-ufp suffix-size next)
  (new split-right-ufp% (suffix-size suffix-size) (next next)))
(define (pad-ufp block-size next)
  (new pad-ufp% (block-size block-size) (next next)))
(define (unpad-ufp next)
  (new unpad-ufp% (next next)))
(define (pop-ufp next)
  (new pop-ufp% (next next)))
(define (push-ufp value next)
  (new push-ufp% (value value) (next next)))
