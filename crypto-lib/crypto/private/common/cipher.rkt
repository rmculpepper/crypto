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
         racket/port
         "interfaces.rkt"
         "catalog.rkt"
         "factory.rkt"
         "common.rkt"
         "random.rkt"
         "error.rkt")
(provide
 (contract-out
  [cipher-default-key-size
   (-> (or/c cipher-spec? cipher-impl? cipher-ctx?) nat?)]
  [cipher-key-sizes
   (-> (or/c cipher-spec? cipher-impl?) (or/c (listof nat?) variable-size?))]
  [cipher-block-size
   (-> (or/c cipher-spec? cipher-impl? cipher-ctx?) nat?)]
  [cipher-iv-size
   (-> (or/c cipher-spec? cipher-impl? cipher-ctx?) nat?)]
  [make-encrypt-ctx
   (->* [cipher/c key/c iv/c] [#:pad pad-mode/c]
        encrypt-ctx?)]
  [make-decrypt-ctx
   (->* [cipher/c key/c iv/c] [#:pad pad-mode/c]
        decrypt-ctx?)]
  [encrypt-ctx?
   (-> any/c boolean?)]
  [decrypt-ctx?
   (-> any/c boolean?)]
  [cipher-update
   (->* [cipher-ctx? bytes?] [nat? nat?]
        bytes?)]
  [cipher-final
   (-> cipher-ctx? bytes?)]

  [encrypt
   (->* [cipher/c key/c iv/c (or/c bytes? string? input-port?)]
        [#:pad pad-mode/c]
        bytes?)]
  [decrypt
   (->* [cipher/c key/c iv/c (or/c bytes? string? input-port?)]
        [#:pad pad-mode/c]
        bytes?)]

  [encrypt-write
   (->* [cipher/c key/c iv/c (or/c bytes? string? input-port?) output-port?]
        [#:pad pad-mode/c]
        nat?)]
  [decrypt-write
   (->* [cipher/c key/c iv/c (or/c bytes? string? input-port?) output-port?]
        [#:pad pad-mode/c]
        nat?)]

  ;; [encrypt-bytes
  ;;  (->* [cipher/c key/c iv/c bytes?] [nat? nat? #:pad pad-mode/c]
  ;;       bytes?)]
  ;; [decrypt-bytes
  ;;  (->* [cipher/c key/c iv/c bytes?] [nat? nat? #:pad pad-mode/c]
  ;;       bytes?)]
  ;; [make-encrypt-pipe
  ;;  (->* [cipher/c key/c iv/c] [#:pad pad-mode/c]
  ;;       (values input-port? output-port?))]
  ;; [make-decrypt-pipe
  ;;  (->* [cipher/c key/c iv/c] [#:pad pad-mode/c]
  ;;       (values input-port? output-port?))]
  ;; [make-encrypt-output-port
  ;;  (->* [cipher/c key/c iv/c output-port?] [#:pad pad-mode/c]
  ;;       output-port?)]
  ;; [make-decrypt-output-port
  ;;  (->* [cipher/c key/c iv/c output-port?] [#:pad pad-mode/c]
  ;;       output-port?)]

  [generate-cipher-key
   (->* [cipher/c] [nat? random-impl?] key/c)]
  [generate-cipher-iv
   (->* [cipher/c] [random-impl?] iv/c)]))

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

(define (cipher-default-key-size o)
  (with-crypto-entry 'cipher-default-key-size
    (cipher-spec-default-key-size (get-spec* o))))
(define (cipher-key-sizes o)
  (with-crypto-entry 'cipher-key-sizes
    (cipher-spec-key-sizes (get-spec* o))))
(define (cipher-block-size o)
  (with-crypto-entry 'cipher-block-size
    (cipher-spec-block-size (get-spec* o))))
(define (cipher-iv-size o)
  (with-crypto-entry 'cipher-iv-size
    (cipher-spec-iv-size (get-spec* o))))



;; ----

(define (encrypt-ctx? x)
  (and (cipher-ctx? x) (send x get-encrypt?)))
(define (decrypt-ctx? x)
  (and (cipher-ctx? x) (not (send x get-encrypt?))))

(define (make-encrypt-ctx ci key iv #:pad [pad? #t])
  (with-crypto-entry 'make-encrypt-ctx
    (-encrypt-ctx ci key iv pad?)))
(define (make-decrypt-ctx ci key iv #:pad [pad? #t])
  (with-crypto-entry 'make-decrypt-ctx
    (-decrypt-ctx ci key iv pad?)))

(define (-encrypt-ctx ci key iv pad)
  (let ([ci (-get-impl ci)])
    (send ci new-ctx key iv #t pad)))
(define (-decrypt-ctx ci key iv pad)
  (let ([ci (-get-impl ci)])
    (send ci new-ctx key iv #f pad)))

(define (cipher-update c ibuf [istart 0] [iend (bytes-length ibuf)])
  (with-crypto-entry 'cipher-update
    (check-input-range 'cipher-update ibuf istart iend)
    (let* ([ilen (- iend istart)]
           [obuf (make-bytes (+ ilen (cipher-block-size c)))]
           [len (send c update! 'cipher-update
                      ibuf istart iend
                      obuf 0 (bytes-length obuf))])
      (shrink-bytes obuf len))))

(define (cipher-final c)
  (with-crypto-entry 'cipher-final
    (let* ([buf (make-bytes (cipher-block-size c))]
           [len (send c final! 'cipher-final buf 0 (bytes-length buf))])
      (shrink-bytes buf len))))

;; ----

;; *crypt : cipher-impl key iv (U bytes string input-port) -> bytes
(define (encrypt ci key iv inp #:pad [pad default-pad])
  (with-crypto-entry 'encrypt
    (*crypt (-encrypt-ctx ci key iv pad) inp)))
(define (decrypt ci key iv inp #:pad [pad default-pad])
  (with-crypto-entry 'decrypt
    (*crypt (-decrypt-ctx ci key iv pad) inp)))

;; *crypt-bytes : cipher-impl key iv bytes [nat nat] -> bytes
(define (encrypt-bytes ci key iv buf [start 0] [end (bytes-length buf)] #:pad [pad default-pad])
  (with-crypto-entry 'encrypt-bytes
    (*crypt-bytes (-encrypt-ctx ci key iv pad) buf start end)))
(define (decrypt-bytes ci key iv buf [start 0] [end (bytes-length buf)] #:pad [pad default-pad])
  (with-crypto-entry 'decrypt-bytes
    (*crypt-bytes (-decrypt-ctx ci key iv pad) buf start end)))

;; *crypt-write : cipher-impl key iv (U bytes string input-port) output-port -> nat
(define (encrypt-write ci key iv inp out #:pad [pad default-pad])
  (with-crypto-entry 'encrypt-write
    (*crypt-write (-encrypt-ctx key iv pad) inp out)))
(define (decrypt-write ci key iv inp out #:pad [pad default-pad])
  (with-crypto-entry 'decrypt-write
    (*crypt-write (-decrypt-ctx key iv pad) inp out)))

;; FIXME: would like to have way of putting read-exn in pipe so padding error
;; shows up on reading side (too?)
(define (make-encrypt-pipe ci key iv #:pad [pad default-pad])
  (with-crypto-entry 'make-encrypt-pipe
    (make-*crypt-pipe (-encrypt-ctx ci key iv pad))))
(define (make-decrypt-pipe ci key iv #:pad [pad default-pad])
  (with-crypto-entry 'make-decrypt-pipe
    (make-*crypt-pipe (-decrypt-ctx ci key iv pad))))

(define (make-encrypt-output-port ci key iv out #:pad [pad default-pad] #:close? [close? #f])
  (with-crypto-entry 'make-encrypt-output-port
    (let ([cctx (-encrypt-ctx ci key iv pad)])
      (make-*crypt-output-port cctx out close?))))
(define (make-decrypt-output-port ci key iv out #:pad [pad default-pad] #:close? [close? #f])
  (with-crypto-entry 'make-decrypt-output-port
    (let ([cctx (-decrypt-ctx ci key iv pad)])
      (make-*crypt-output-port cctx out close?))))

;; *crypt-copy-port : ci key iv input-port output-port -> void
(define (encrypt-copy-port ci key iv in out #:pad [pad default-pad])
  (with-crypto-entry 'encrypt-copy-port
    (let ([cctx (-encrypt-ctx ci key iv #:pad pad)])
      (*crypt-copy-port cctx in out))))
(define (decrypt-copy-port ci key iv in out #:pad [pad default-pad])
  (with-crypto-entry 'decrypt-copy-port
    (let ([cctx (-decrypt-ctx ci key iv #:pad pad)])
      (*crypt-copy-port cctx in out))))

;; ----

(define (*crypt cctx inp)
  (cond [(bytes? inp) (*crypt-bytes cctx inp 0 (bytes-length inp))]
        [(string? inp) (*crypt cctx (open-input-string inp))]
        [(input-port? inp)
         (let ([out (open-output-bytes)])
           (*crypt-copy-port cctx inp out)
           (get-output-bytes out))]))

(define (*crypt-bytes cctx buf start end)
  (check-input-range buf start end)
  (define enc-len (+ (cipher-block-size cctx) (- end start)))
  (define enc-buf (make-bytes enc-len))
  (let* ([len1 (send cctx update! buf start end enc-buf 0 enc-len)]
         [len2 (send cctx final! enc-buf len1 enc-len)])
    (shrink-bytes enc-buf (+ len1 len2))))

(define (*crypt-write cctx inp out)
  (cond [(bytes? inp) (*crypt-copy-port cctx (open-input-bytes inp) out)]
        [(string? inp) (*crypt-write cctx (open-input-string inp) out)]
        [(input-port? inp) (*crypt-copy-port cctx inp out)]))

(define (make-*crypt-pipe cctx)
  (define-values (pin pout) (make-pipe))
  (values pin (make-*crypt-output-port cctx pout #t)))

(define (make-*crypt-input-port cctx in close?)
  (define-values (pin pout) (make-pipe))
  (thread (lambda ()
            (*crypt-copy-port cctx in pout)
            (close-output-port pout)))
  pin)

(define (make-*crypt-output-port cctx out close?)
  (define BLOCKS-AT-ONCE 8)
  (define block-size (cipher-block-size cctx))
  ;; Assumes no padding adds more than one extra block
  (define enc-buf (make-bytes (* (+ 1 BLOCKS-AT-ONCE) block-size)))
  (define name (object-name out)) ;; FIXME: add "encrypt-"/"decrypt-"
  (define evt always-evt)
  (define (write-out buf start end _sync? _eb?)
    (if (= start end)
        (begin (flush-output out) 0)
        (let* ([len* (min (- end start) (* BLOCKS-AT-ONCE block-size))]
               [enc-len (send cctx update! buf start (+ start len*)
                              enc-buf 0 (bytes-length enc-buf))])
          (write-bytes enc-buf out 0 enc-len)
          len*)))
  (define (close)
    ;; FIXME: If final! fails w/ padding error, want to propagate to
    ;; other end of port (if pipe)...
    (let ([enc-len (send cctx final! enc-buf 0 (bytes-length enc-buf))])
      (write-bytes enc-buf out 0 enc-len)
      (when close?
        (close-output-port out))))
  (make-output-port name evt write-out close))

(define (*crypt-copy-port cctx inp outp)
  (define BLOCKS-AT-ONCE 8)
  (define block-size (cipher-block-size cctx))
  (define ibuf (make-bytes (* block-size BLOCKS-AT-ONCE)))
  (define obuf (make-bytes (* block-size (+ 1 BLOCKS-AT-ONCE))))
  (let loop ()
    (let ([icount (read-bytes-avail! ibuf inp)])
      (cond [(eof-object? icount)
             ;; FIXME: handle cipher-final! error...
             (let ([ocount (send cctx final! obuf 0 (bytes-length obuf))])
               (write-bytes obuf outp 0 ocount)
               (flush-output outp)
               (void))]
            [else
             (let ([ocount (send cctx update! ibuf 0 icount
                                 obuf 0 (bytes-length obuf))])
               (write-bytes obuf outp 0 ocount)
               (loop))]))))

;; ----

(define (generate-cipher-key ci [size (cipher-default-key-size ci)] [rand #f])
  (with-crypto-entry 'generate-cipher-key
    (let* ([ci (-get-impl ci)]
           [rand (or rand (get-random* ci))])
      ;; FIXME: any way to check for weak keys, avoid???
      (random-bytes size rand))))

(define (generate-cipher-iv ci [rand #f])
  (with-crypto-entry 'generate-cipher-iv
    (let* ([ci (-get-impl ci)]
           [rand (or rand (get-random* ci))])
      (let ([size (cipher-iv-size ci)])
        (and (positive? size) (random-bytes size))))))
