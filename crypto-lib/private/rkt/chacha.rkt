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
(require racket/vector
         "poly1305.rkt")
(provide (all-defined-out))

;; Reference: https://tools.ietf.org/html/rfc7539

;; ============================================================

(module chacha-safe racket/base
  (require racket/vector)
  (provide (all-defined-out))

  ;; A U32 is an exact integer in [0, 2^32-1].
  ;; State is (vector U32*8)

  ;; Operations on U32s:
  (define (u32 x) (bitwise-and x #xFFFFFFFF))
  (define (u+ x y) (u32 (+ x y)))
  (define (u^ x y) (bitwise-xor x y))
  (define (u<<< x n)
    (bitwise-xor (bitwise-bit-field x (- 32 n) 32)
                 (arithmetic-shift (bitwise-bit-field x 0 (- 32 n)) n)))

  ;; chacha-init : Bytes Bytes -> State
  (define (chacha-init key nonce)
    (vector #x61707865 #x3320646e #x79622d32 #x6b206574
            (integer-bytes->integer key #f #f  0  4)
            (integer-bytes->integer key #f #f  4  8)
            (integer-bytes->integer key #f #f  8 12)
            (integer-bytes->integer key #f #f 12 16)
            (integer-bytes->integer key #f #f 16 20)
            (integer-bytes->integer key #f #f 20 24)
            (integer-bytes->integer key #f #f 24 28)
            (integer-bytes->integer key #f #f 28 32)
            0 ;; counter
            (integer-bytes->integer nonce #f #f 0 4)
            (integer-bytes->integer nonce #f #f 4 8)
            (integer-bytes->integer nonce #f #f 8 12)))

  ;; Qround : State Nat*4 -> Void
  (define (Qround s n1 n2 n3 n4)
    (define a (vector-ref s n1))
    (define b (vector-ref s n2))
    (define c (vector-ref s n3))
    (define d (vector-ref s n4))
    (let* (;; a += b; d ^= a; d <<<= 16;
           [a (u+ a b)] [d (u^ d a)] [d (u<<< d 16)]
           ;; c += d; b ^= c; b <<<= 12;
           [c (u+ c d)] [b (u^ b c)] [b (u<<< b 12)]
           ;; a += b; d ^= a; d <<<= 8;
           [a (u+ a b)] [d (u^ d a)] [d (u<<< d 8)]
           ;; c += d; b ^= c; b <<<= 7;
           [c (u+ c d)] [b (u^ b c)] [b (u<<< b 7)])
      (vector-set! s n1 a)
      (vector-set! s n2 b)
      (vector-set! s n3 c)
      (vector-set! s n4 d)))

  ;; chacha : State Nat Nat -> State
  (define (chacha protostate ctr drounds)
    (define init-state (vector-copy protostate))
    (vector-set! init-state 12 ctr)
    (define state (vector-copy init-state))
    (for ([i (in-range drounds)])
      (Qround state 0 4  8 12)
      (Qround state 1 5  9 13)
      (Qround state 2 6 10 14)
      (Qround state 3 7 11 15)
      (Qround state 0 5 10 15)
      (Qround state 1 6 11 12)
      (Qround state 2 7  8 13)
      (Qround state 3 4  9 14))
    (for ([i (in-range 16)])
      (vector-set! state i (u+ (vector-ref state i) (vector-ref init-state i))))
    state)

  ;; state-xor-bytes : State Bytes Nat -> Void
  (define (state-xor-bytes s buf start)
    (for ([n (in-vector s)] [i (in-range start (+ start 64) 4)])
      (define w1 (integer-bytes->integer buf #f #f i (+ i 4)))
      (define w2 (bitwise-xor w1 n))
      (integer->integer-bytes w2 4 #f #f buf i))))

;; ============================================================

(module chacha-fx racket/base
  (require (for-syntax racket/base racket/syntax)
           racket/unsafe/ops
           racket/fixnum)
  (provide (protect-out (all-defined-out)))

  ;; A U32 is a fixnum in [0, 2^32-1]
  ;; State is FXVector[8] (where each element is a 32-bit unsigned integer)

  ;; Operations on U32s:
  (define (u32 x) (unsafe-fxand x #xFFFFFFFF))
  (define (u+ x y) (u32 (unsafe-fx+ x y)))
  (define (u^ x y) (unsafe-fxxor x y))
  (define (u<<< x n)
    (u32 (unsafe-fxior (unsafe-fxlshift x n)
                       (unsafe-fxrshift x (- 32 n)))))

  ;; chacha-init : Bytes Bytes -> State
  (define (chacha-init key nonce)
    (fxvector #x61707865 #x3320646e #x79622d32 #x6b206574
              (integer-bytes->integer key #f #f  0  4)
              (integer-bytes->integer key #f #f  4  8)
              (integer-bytes->integer key #f #f  8 12)
              (integer-bytes->integer key #f #f 12 16)
              (integer-bytes->integer key #f #f 16 20)
              (integer-bytes->integer key #f #f 20 24)
              (integer-bytes->integer key #f #f 24 28)
              (integer-bytes->integer key #f #f 28 32)
              0 ;; counter
              (integer-bytes->integer nonce #f #f 0 4)
              (integer-bytes->integer nonce #f #f 4 8)
              (integer-bytes->integer nonce #f #f 8 12)))

  (define-syntax-rule (with-QR (a b c d) . body)
    (let* (;; a += b; d ^= a; d <<<= 16;
           [a (u+ a b)] [d (u^ d a)] [d (u<<< d 16)]
           ;; c += d; b ^= c; b <<<= 12;
           [c (u+ c d)] [b (u^ b c)] [b (u<<< b 12)]
           ;; a += b; d ^= a; d <<<= 8;
           [a (u+ a b)] [d (u^ d a)] [d (u<<< d 8)]
           ;; c += d; b ^= c; b <<<= 7;
           [c (u+ c d)] [b (u^ b c)] [b (u<<< b 7)])
      . body))

  ;; Qround : State Nat*4 -> Void
  (define (Qround s n1 n2 n3 n4)
    (define a (fxvector-ref s n1))
    (define b (fxvector-ref s n2))
    (define c (fxvector-ref s n3))
    (define d (fxvector-ref s n4))
    (with-QR (a b c d)
      (fxvector-set! s n1 a)
      (fxvector-set! s n2 b)
      (fxvector-set! s n3 c)
      (fxvector-set! s n4 d)))

  ;; double-round : State -> State
  (define (double-round state)
    (Qround state 0 4  8 12)
    (Qround state 1 5  9 13)
    (Qround state 2 6 10 14)
    (Qround state 3 7 11 15)
    (Qround state 0 5 10 15)
    (Qround state 1 6 11 12)
    (Qround state 2 7  8 13)
    (Qround state 3 4  9 14))

  ;; double-round* : State -> State
  (define (double-round* state)
    (define-syntax with-QR*
      (syntax-rules ()
        [(with-QR* () . body)
         (let () . body)]
        [(with-QR* (clause . clauses) . body)
         (with-QR clause (with-QR* clauses . body))]))
    (define-syntax (load/store stx)
      (with-syntax ([(i ...)  (for/list ([i (in-range 16)]) i)]
                    [(si ...) (for/list ([i (in-range 16)]) (format-id stx "s~a" i))])
        (syntax-case stx ()
          [(_ #:load)  #'(begin (define si (fxvector-ref state i)) ...)]
          [(_ #:store) #'(begin (fxvector-set! state i si) ...)])))
    (load/store #:load)
    (with-QR* ((s0 s4 s8  s12)
               (s1 s5 s9  s13)
               (s2 s6 s10 s14)
               (s3 s7 s11 s15)
               (s0 s5 s10 s15)
               (s1 s6 s11 s12)
               (s2 s7 s8  s13)
               (s3 s4 s9  s14))
      (load/store #:store)))

  ;; chacha : State Nat Nat -> State
  (define (chacha protostate ctr drounds)
    (define init-state (fxvector-copy protostate))
    (fxvector-set! init-state 12 ctr)
    (define state (fxvector-copy init-state))
    (for ([i (in-range drounds)])
      (double-round* state))
    (for ([i (in-range 16)])
      (fxvector-set! state i (u+ (fxvector-ref state i) (fxvector-ref init-state i))))
    state)

  ;; state-xor-bytes : State Bytes Nat -> Void
  (define (state-xor-bytes s buf start)
    (for ([n (in-fxvector s)] [i (in-range start (+ start 64) 4)])
      (define w1 (integer-bytes->integer buf #f #f i (+ i 4)))
      (define w2 (unsafe-fxxor w1 n))
      (integer->integer-bytes w2 4 #f #f buf i))))

;; ============================================================

(require (prefix-in gen: 'chacha-safe)
         (prefix-in fx:  'chacha-fx))

(define chacha-init
  (if (fixnum? #xFFFFFFFF) fx:chacha-init gen:chacha-init))
(define chacha
  (if (fixnum? #xFFFFFFFF) fx:chacha gen:chacha))
(define state-xor-bytes
  (if (fixnum? #xFFFFFFFF) fx:state-xor-bytes gen:state-xor-bytes))

(define (chacha20 key nonce msg [init-ctr 0])
  (define protostate (chacha-init key nonce))
  (chacha20* protostate msg init-ctr))

(define (chacha20* protostate msg init-ctr)
  (define msglen (bytes-length msg))
  (define buf (make-bytes (* 64 (quotient (+ msglen 63) 64))))
  (bytes-copy! buf 0 msg 0)
  (for ([ctr (in-naturals init-ctr)] [start (in-range 0 msglen 64)])
    (define s (chacha protostate ctr 10))
    (state-xor-bytes s buf start))
  (subbytes buf 0 msglen))

;; state->bytes : State -> Bytes
(define (state->bytes s)
  (define buf (make-bytes 64))
  (state-xor-bytes s buf 0)
  buf)

(define AUTHLEN 16)

(define (chacha20-poly1305-encrypt key nonce msg aad)
  (define protostate (chacha-init key nonce))
  (define s0 (chacha protostate 0 10))
  (define keybuf (state->bytes s0))
  (define ctext (chacha20* protostate msg 1))
  (define auth
    (let ([msg* (bytes-append aad
                              (make-bytes (modulo (- (bytes-length aad)) 16))
                              ctext
                              (make-bytes (modulo (- (bytes-length ctext)) 16))
                              (integer->integer-bytes (bytes-length aad) 8 #f #f)
                              (integer->integer-bytes (bytes-length ctext) 8 #f #f))])
      (poly1305 keybuf msg*)))
  (bytes-append ctext auth))

(define (chacha20-poly1305-decrypt key nonce msg aad)
  (define protostate (chacha-init key nonce))
  (define s0 (chacha protostate 0 10))
  (define keybuf (state->bytes s0))
  (define ctext (subbytes msg 0 (- (bytes-length msg) AUTHLEN)))
  (define auth (subbytes msg (- (bytes-length msg) AUTHLEN) (bytes-length msg)))
  (define auth*
    (let ([msg* (bytes-append aad
                              (make-bytes (modulo (- (bytes-length aad)) 16))
                              ctext
                              (make-bytes (modulo (- (bytes-length ctext)) 16))
                              (integer->integer-bytes (bytes-length aad) 8 #f #f)
                              (integer->integer-bytes (bytes-length ctext) 8 #f #f))])
      (poly1305 keybuf msg*)))
  (if (equal? auth auth*) (chacha20* protostate ctext 1) #f))
