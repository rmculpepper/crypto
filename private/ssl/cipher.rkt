;; mzcrypto: libcrypto bindings for PLT-scheme
;; symmetric ciphers
;; 
;; (C) Copyright 2007-2009 Dimitris Vyzovitis <vyzo at media.mit.edu>
;; 
;; mzcrypto is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as published
;; by the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;; 
;; mzcrypto is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Lesser General Public License for more details.
;; 
;; You should have received a copy of the GNU Lesser General Public License
;; along with mzcrypto.  If not, see <http://www.gnu.org/licenses/>.

#lang racket/base
(require ffi/unsafe
         racket/class
         racket/match
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "ffi.rkt"
         "macros.rkt"
         "rand.rkt"
         "util.rkt"
         (for-syntax racket/base
                     racket/syntax))

;; ============================================================

(define cipher-impl%
  (class* object% (cipher-impl<%>)
    (init-field cipher
                name)

    (define-values (block-size key-size iv-size)
      (match (ptr-ref cipher (_list-struct _int _int _int _int))
        [(list _ size keylen ivlen)
         (values size keylen (and (> ivlen 0) ivlen))]))

    (define/public (get-name) (symbol->string name))
    (define/public (get-key-size) key-size)
    (define/public (get-block-size) block-size)
    (define/public (get-iv-size) iv-size)

    (define/public (new-ctx who key iv enc? pad?)
      (unless (and (bytes? key) (>= (bytes-length key) key-size))
        (error who "bad key: ~e" key))
      (when iv-size
        (unless (and (bytes? iv) (>= (bytes-length iv) iv-size))
          (error who "bad iv: ~e" iv)))
      (let ([ctx (EVP_CIPHER_CTX_new)])
        (EVP_CipherInit_ex ctx cipher key (and iv-size iv) enc?)
        (EVP_CIPHER_CTX_set_padding ctx pad?)
        (new cipher-ctx% (impl this) (ctx ctx) (encrypt? enc?))))

    (super-new)
    ))

(define cipher-ctx%
  (class* base-ctx% (cipher-ctx<%>)
    (init-field ctx
                encrypt?)
    (inherit-field impl)
    (super-new)

    (define/public (get-encrypt?) encrypt?)

    (define/public (update! who inbuf instart inend outbuf outstart outend)
      (unless ctx (error who "cipher context is closed"))
      (check-input-range who inbuf instart inend)
      (check-output-range who outbuf outstart outend (maxlen (- inend instart)))
      (EVP_CipherUpdate ctx (ptr-add outbuf outstart)
                        (ptr-add inbuf instart)
                        (- inend instart)))

    (define/public (final! who outbuf outstart outend)
      (unless ctx (error who "cipher context is closed"))
      (check-output-range who outbuf outstart outend (maxlen 0))
      (begin0 (EVP_CipherFinal_ex ctx (ptr-add outbuf outstart))
        (EVP_CIPHER_CTX_free ctx)
        (set! ctx #f)))

    (define/private (maxlen inlen)
      (+ inlen (send impl get-block-size)))

    ))

;; ============================================================

(define (!cipher? x) (is-a? x cipher-impl%))
(define (cipher? x) (is-a? x cipher-ctx%))
(define (cipher-encrypt? x) (send x get-encrypt?))

(define (cipher-block-size obj)
  (get-cipher-prop 'cipher-block-size obj (lambda (o) (send o get-block-size))))
(define (cipher-key-length obj)
  (get-cipher-prop 'cipher-key-length obj (lambda (o) (send o get-key-size))))
(define (cipher-iv-length obj)
  (get-cipher-prop 'cipher-iv-length obj (lambda (o) (send o get-iv-size))))

(define (get-cipher-prop who obj getter)
  (cond [(is-a? obj cipher-impl<%>) (getter obj)]
        [(is-a? obj cipher-ctx<%>) (getter (send obj get-impl))]
        [else (raise-type-error who "cipher implementation or cipher context" obj)]))

;; --

(define (cipher-new ci key iv enc? pad?)
  (send ci new-ctx 'cipher-new key iv enc? pad?))

(define (cipher-encrypt type key iv #:padding [pad? #t])
  (cipher-new type key iv #t pad?))

(define (cipher-decrypt type key iv #:padding [pad? #t])
  (cipher-new type key iv #f pad?))

;; FIXME: interface
(define cipher-update!
  (case-lambda
    [(c ibs)
     (let* ([obs (make-bytes (+ (bytes-length ibs) (cipher-block-size c)))]
            [len (cipher-update! c ibs obs)])
       (shrink-bytes obs len))]
    [(c ibs obs)
     (send c update! 'cipher-update!
           ibs 0 (bytes-length ibs)
           obs 0 (bytes-length obs))]
    [(c ibs obs istart iend ostart oend)
     (send c update! 'cipher-update!
           ibs istart iend
           obs ostart oend)]))

;; FIXME: interface
(define cipher-final!
  (case-lambda
    [(c)
     (let* ([bs (make-bytes (cipher-block-size c))]
            [len (cipher-final! c bs)])
       (shrink-bytes bs len))]
    [(c obs)
     (send c final! 'cipher-final! obs 0 (bytes-length obs))]
    [(c obs ostart)
     (send c final! 'cipher-final! obs ostart (bytes-length obs))]
    [(c obs ostart oend)
     (send c final! 'cipher-final! obs ostart oend)]))

;; ----

(define (cipher-pipe cipher inp outp)
  (let* ([1b (cipher-block-size cipher)]
         [2b (* 2 1b)]
         [ibuf (make-bytes 1b)]
         [obuf (make-bytes 2b)])
    (let lp ([icount (read-bytes-avail! ibuf inp)])
      (if (eof-object? icount)
          (let ([ocount (cipher-final! cipher obuf)])
            (write-bytes obuf outp 0 ocount)
            (flush-output outp)
            (void))
          (let ([ocount (cipher-update! cipher ibuf obuf 0 icount 0 2b)])
            (write-bytes obuf outp 0 ocount)
            (lp (read-bytes-avail! ibuf inp)))))))

(define (make-cipher-pipe-fun who init)
  (case-lambda
    [(ci key iv)
     (let-values ([(cipher) (init ci key iv)]
                  [(rd1 wr1) (make-pipe)]
                  [(rd2 wr2) (make-pipe)])
       (thread (lambda ()
                 (cipher-pipe cipher rd1 wr2)
                 (close-input-port rd1)
                 (close-output-port wr2)))
       (values rd2 wr1))]
    [(ci key iv inp)
     (cond [(bytes? inp) 
            (let ([outp (open-output-bytes)])
              (cipher-pipe (init ci key iv) (open-input-bytes inp) outp)
              (get-output-bytes outp))]
           [(input-port? inp)
            (let-values ([(cipher) (init ci key iv)]
                         [(rd wr) (make-pipe)])
              (thread (lambda () 
                        (cipher-pipe cipher inp wr)
                        (close-output-port wr)))
              rd)]
           [else (raise-type-error who "bytes or input-port" inp)])]
    [(ci key iv inp outp)
     (unless (output-port? outp)
       (raise-type-error who "output-port" outp))
     (cond [(bytes? inp)
            (cipher-pipe (init ci key iv) (open-input-bytes inp) outp)]
           [(input-port? inp)
            (cipher-pipe (init ci key iv) inp outp)]
           [else (raise-type-error who "bytes or input-port" inp)])]))

(define encrypt (make-cipher-pipe-fun 'encrypt cipher-encrypt))
(define decrypt (make-cipher-pipe-fun 'decrypt cipher-decrypt))

;; ============================================================

(define (generate-cipher-key ci)
  (let ([klen (send ci get-key-size)]
        [ivlen (send ci get-iv-size)])
    (values (random-bytes klen) 
            (and ivlen (pseudo-random-bytes ivlen)))))

;; ============================================================

(define-symbols cipher.symbols
  !cipher?
  cipher?
  cipher-encrypt?
  cipher-block-size cipher-key-length cipher-iv-length
  cipher-encrypt cipher-decrypt cipher-update! cipher-final!
  encrypt decrypt)

(define-provider provide-cipher cipher.symbols)

(provide (all-defined-out))

#|
(provide-cipher)
(provide provide-cipher generate-cipher-key)
|#
