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
(require racket/vector)
(provide (all-defined-out))

;; Reference: https://cr.yp.to/salsa20.html

;; Key is 32 bytes, nonce is 8 bytes, counter is 8 bytes.

;; ============================================================

(module salsa-safe racket/base
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

  ;; salsa-init : Bytes[32] Bytes[8] -> State
  (define (salsa-init key nonce)
    (vector #x61707865
            (integer-bytes->integer key #f #f  0  4)
            (integer-bytes->integer key #f #f  4  8)
            (integer-bytes->integer key #f #f  8 12)
            (integer-bytes->integer key #f #f 12 16)
            #x3320646e
            (integer-bytes->integer nonce #f #f 0 4)
            (integer-bytes->integer nonce #f #f 4 8)
            0 0 ;; counter @ state[8,9]
            #x79622d32
            (integer-bytes->integer key #f #f 16 20)
            (integer-bytes->integer key #f #f 20 24)
            (integer-bytes->integer key #f #f 24 28)
            (integer-bytes->integer key #f #f 28 32)
            #x6b206574))

  ;; step : State Nat*4 -> Void
  (define (step s n1 n2 n3 shift)
    ;; s[n1] ^= R(s[n2]+s[n3], shift)
    (vector-set! s n1
                 (u^ (vector-ref s n1)
                     (u<<< (u+ (vector-ref s n2) (vector-ref s n3)) shift))))

  (define (double-round s)
    ;; x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
    (step s 4 0 12 7) (step s 8 4 0 9)
    ;; x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);
    (step s 12 8 4 13) (step s 0 12 8 18)
    ;; x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
    (step s 9 5 1 7) (step s 13 9 5 9)
    ;; x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);
    (step s 1 13 9 13) (step s 5 1 13 18)
    ;; x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
    (step s 14 10 6 7) (step s 2 14 10 9)
    ;; x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);
    (step s 6 2 14 13) (step s 10 6 2 18)
    ;; x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
    (step s 3 15 11 7) (step s 7 3 15 9)
    ;; x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);
    (step s 11 7 3 13) (step s 15 11 7 18)
    ;; x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
    (step s 1 0 3 7) (step s 2 1 0 9)
    ;; x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);
    (step s 3 2 1 13) (step s 0 3 2 18)
    ;; x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
    (step s 6 5 4 7) (step s 7 6 5 9)
    ;; x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);
    (step s 4 7 6 13) (step s 5 4 7 18)
    ;; x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
    (step s 11 10 9 7) (step s 8 11 10 9)
    ;; x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);
    (step s 9 8 11 13) (step s 10 9 8 18)
    ;; x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
    (step s 12 15 14 7) (step s 13 12 15 9)
    ;; x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
    (step s 14 13 12 13) (step s 15 14 13 18))

  ;; salsa : State Nat Nat -> State
  (define (salsa protostate ctr drounds)
    (define init-state (vector-copy protostate))
    (vector-set! init-state 8 (bitwise-bit-field ctr  0 32))
    (vector-set! init-state 9 (bitwise-bit-field ctr 32 64))
    (define state (vector-copy init-state))
    (for ([i (in-range drounds)])
      (double-round state))
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

(module salsa-fx racket/base
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

  ;; salsa-init : Bytes Bytes -> State
  (define (salsa-init key nonce)
    (fxvector #x61707865
              (integer-bytes->integer key #f #f  0  4)
              (integer-bytes->integer key #f #f  4  8)
              (integer-bytes->integer key #f #f  8 12)
              (integer-bytes->integer key #f #f 12 16)
              #x3320646e
              (integer-bytes->integer nonce #f #f 0 4)
              (integer-bytes->integer nonce #f #f 4 8)
              0 0 ;; counter @ state[8,9]
              #x79622d32
              (integer-bytes->integer key #f #f 16 20)
              (integer-bytes->integer key #f #f 20 24)
              (integer-bytes->integer key #f #f 24 28)
              (integer-bytes->integer key #f #f 28 32)
              #x6b206574))

  ;; double-round : State -> State
  (define (double-round state)
    (define-syntax with-steps
      (syntax-rules ()
        [(with-steps () . body)
         (let () . body)]
        [(with-steps ((a b c d) . clauses) . body)
         (let ([a (u^ a (u<<< (u+ b c) d))]) (with-steps clauses . body))]))
    (define-syntax (load/store stx)
      (with-syntax ([(i ...)  (for/list ([i (in-range 16)]) i)]
                    [(si ...) (for/list ([i (in-range 16)]) (format-id stx "s~a" i))])
        (syntax-case stx ()
          [(_ #:load)  #'(begin (define si (fxvector-ref state i)) ...)]
          [(_ #:store) #'(begin (fxvector-set! state i si) ...)])))
    (load/store #:load)
    (with-steps ((s4  s0  s12 7)  (s8  s4  s0  9)
                 (s12 s8  s4  13) (s0  s12 s8  18)
                 (s9  s5  s1  7)  (s13 s9  s5  9)
                 (s1  s13 s9  13) (s5  s1  s13 18)
                 (s14 s10 s6  7)  (s2  s14 s10 9)
                 (s6  s2  s14 13) (s10 s6  s2  18)
                 (s3  s15 s11 7)  (s7  s3  s15 9)
                 (s11 s7  s3  13) (s15 s11 s7  18)
                 (s1  s0  s3  7)  (s2  s1  s0  9)
                 (s3  s2  s1  13) (s0  s3  s2  18)
                 (s6  s5  s4  7)  (s7  s6  s5  9)
                 (s4  s7  s6  13) (s5  s4  s7  18)
                 (s11 s10 s9  7)  (s8  s11 s10 9)
                 (s9  s8  s11 13) (s10 s9  s8  18)
                 (s12 s15 s14 7)  (s13 s12 s15 9)
                 (s14 s13 s12 13) (s15 s14 s13 18))
      (load/store #:store)))

  ;; salsa : State Nat Nat -> State
  (define (salsa protostate ctr drounds)
    (define init-state (fxvector-copy protostate))
    (fxvector-set! init-state 8 (bitwise-bit-field ctr 0  32))
    (fxvector-set! init-state 9 (bitwise-bit-field ctr 32 64))
    (define state (fxvector-copy init-state))
    (for ([i (in-range drounds)])
      (double-round state))
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

(require (prefix-in gen: 'salsa-safe)
         (prefix-in fx:  'salsa-fx))

(define salsa-init
  (if (fixnum? #xFFFFFFFF) fx:salsa-init gen:salsa-init))
(define salsa
  (if (fixnum? #xFFFFFFFF) fx:salsa gen:salsa))
(define state-xor-bytes
  (if (fixnum? #xFFFFFFFF) fx:state-xor-bytes gen:state-xor-bytes))

(define (salsa20 key nonce msg [init-ctr 0])
  (define protostate (salsa-init key nonce))
  (salsa20* protostate msg init-ctr))

(define (salsa20* protostate msg init-ctr)
  (define msglen (bytes-length msg))
  (define buf (make-bytes (* 64 (quotient (+ msglen 63) 64))))
  (bytes-copy! buf 0 msg 0)
  (for ([ctr (in-naturals init-ctr)] [start (in-range 0 msglen 64)])
    (define s (salsa protostate ctr 10))
    (state-xor-bytes s buf start))
  (subbytes buf 0 msglen))

;; hsalsa20 : Bytes[32] Bytes[16] -> Bytes[32]
(define (hsalsa20 key nonce)
  (define nonce* (subbytes nonce 0 8))
  (define ctr* (+ (arithmetic-shift (integer-bytes->integer nonce #f #f 8 12) 32)
                  (integer-bytes->integer nonce #f #f 12 16)))
  (define protostate (salsa-init key nonce*))
  (define buf (make-bytes 64))
  (define s (salsa protostate ctr* 10))
  (state-xor-bytes s buf 0)
  (define (select-words indexes)
    (define out (make-bytes (* 4 (length indexes)) 0))
    (for ([outi (in-naturals)] [index (in-list indexes)])
      (integer->integer-bytes
       (integer-bytes->integer buf #f #f (* index 4) (* (add1 index) 4))
       4 #f #f out (* 4 outi)))
    out)
  (select-words 0 5 10 15 6 7 8 9))
