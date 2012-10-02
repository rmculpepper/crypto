#lang racket/base
(require racket/class
         racket/contract/base
         racket/port
         "interfaces.rkt"
         "common.rkt")
(provide
 (contract-out
  [cipher-impl?
   (-> any/c boolean?)]
  [cipher-ctx?
   (-> any/c boolean?)]
  [cipher-block-size
   (-> (or/c cipher-impl? cipher-ctx?) nat?)]
  [cipher-key-size
   (-> (or/c cipher-impl? cipher-ctx?) nat?)]
  [cipher-iv-size
   (-> (or/c cipher-impl? cipher-ctx?) nat?)]
  [make-encrypt-cipher-ctx
   (->* (cipher-impl? key/c iv/c) (#:pad? any/c)
        cipher-ctx?)]
  [make-decrypt-cipher-ctx
   (->* (cipher-impl? key/c iv/c) (#:pad? any/c)
        cipher-ctx?)]
  [cipher-encrypt?
   (-> cipher-ctx? boolean?)]
  [cipher-update
   (->* (cipher-ctx? bytes?) (nat? nat?)
        bytes?)]
  [cipher-update!
   (->* (cipher-ctx? bytes? bytes?)
        (nat? nat? nat? nat?)
        nat?)]
  [cipher-final
   (-> cipher-ctx? bytes?)]
  [cipher-final!
   (->* (cipher-ctx? bytes?) (nat? nat?) nat?)]
  [encrypt
   (case->
    (-> cipher-impl? key/c iv/c
        (values input-port? output-port?))
    (-> cipher-impl? key/c iv/c (or/c input-port? bytes?)
        input-port?)
    (-> cipher-impl? key/c iv/c (or/c input-port? bytes?) output-port?
        void?))]
  [decrypt
   (case->
    (-> cipher-impl? key/c iv/c
        (values input-port? output-port?))
    (-> cipher-impl? key/c iv/c (or/c input-port? bytes?)
        input-port?)
    (-> cipher-impl? key/c iv/c (or/c input-port? bytes?) output-port?
        void?))]
  [generate-cipher-key+iv
   (-> cipher-impl? (values key/c iv/c))]))

(define nat? exact-nonnegative-integer?)
(define key/c bytes?)
(define iv/c (or/c bytes? #f))

;; ----

(define (cipher-impl? x) (is-a? cipher-impl<%>))
(define (cipher-ctx? x) (is-a? cipher-ctx?))
(define (cipher-encrypt? x) (send x get-encrypt?))

(define (cipher-block-size obj)
  (get-cipher-prop obj (lambda (o) (send o get-block-size))))
(define (cipher-key-size obj)
  (get-cipher-prop obj (lambda (o) (send o get-key-size))))
(define (cipher-iv-size obj)
  (get-cipher-prop obj (lambda (o) (send o get-iv-size))))

(define (get-cipher-prop obj getter)
  (cond [(is-a? obj cipher-impl<%>) (getter obj)]
        [(is-a? obj cipher-ctx<%>) (getter (send obj get-impl))]))

;; ----

(define (make-encrypt-cipher-ctx ci key iv #:pad? [pad? #t])
  (send ci new-ctx 'make-encrypt-cipher-ctx key iv #t pad?))

(define (make-decrypt-cipher-ctx ci key iv #:pad? [pad? #t])
  (send ci new-ctx 'make-decrypt-cipher-ctx key iv #f pad?))

(define (cipher-update c ibuf [istart 0] [iend (bytes-length ibuf)])
  (let* ([ilen (max 0 (- iend istart))] ;; istart<=iend not yet checked
         [obuf (make-bytes (+ ilen (cipher-block-size c)))]
         [len (send c update! 'cipher-update
                    ibuf istart iend
                    obuf 0 (bytes-length obuf))])
    (shrink-bytes obuf len)))

(define (cipher-update! c ibuf obuf
                        [istart 0] [iend (bytes-length ibuf)]
                        [ostart 0] [oend (bytes-length obuf)])
  (send c update! 'cipher-update! ibuf istart iend obuf ostart oend))

(define (cipher-final c)
  (let* ([buf (make-bytes (cipher-block-size c))]
         [len (send c final! 'cipher-final! buf 0 (bytes-length buf))])
    (shrink-bytes buf len)))

(define (cipher-final! c buf [start 0] [end (bytes-length buf)])
  (send c final! 'cipher-final! buf start end))

;; ----

(define (cipher-pump cipher inp outp)
  (let* ([block-size (cipher-block-size cipher)]
         [ibuf (make-bytes (* 8 block-size))]
         [obuf (make-bytes (* 9 block-size))])
    (let loop ()
      (let ([icount (read-bytes-avail! ibuf inp)])
        (cond [(eof-object? icount)
               (let ([ocount (cipher-final! cipher obuf)])
                 (write-bytes obuf outp 0 ocount)
                 (flush-output outp)
                 (void))]
              [else
               (let ([ocount (cipher-update! cipher ibuf obuf 0 icount)])
                 (write-bytes obuf outp 0 ocount)
                 (loop))])))))

(define (*crypt-pipe who init ci key iv)
  (define cipher (init ci key iv))
  (define block-size (cipher-block-size cipher))
  (define-values (enc-in enc-out) (make-pipe))
  (define 8blocks (* 8 block-size))
  (define enc-buf (make-bytes (* 9 block-size)))
  (define name (string->symbol (format "~a-pipe" who)))
  (define evt always-evt)
  (define (write-out buf start end _sync? _eb?)
    (let* ([len* (min (- end start) 8blocks)]
           [enc-len (cipher-update! cipher buf enc-buf start (+ start len*))])
      (write-bytes enc-buf enc-out 0 enc-len)
      len*))
  (define (close)
    (let ([enc-len (cipher-final! cipher enc-buf)])
      (write-bytes enc-buf enc-out 0 enc-len)
      (close-output-port enc-out)))
  (make-output-port name evt write-out close))

#|
(define (*crypt-pipe who init ci key iv)
  (let-values ([(cipher) (init ci key iv)]
               [(rd1 wr1) (make-pipe)]
               [(rd2 wr2) (make-pipe)])
    (thread (lambda ()
              (cipher-pump cipher rd1 wr2)
              (close-input-port rd1)
              (close-output-port wr2)))
    (values rd2 wr1)))
|#

(define (*crypt-input who init ci key iv inp)
  (cond [(bytes? inp) 
         (let ([outp (open-output-bytes)])
           (cipher-pump (init ci key iv) (open-input-bytes inp) outp)
           (get-output-bytes outp))]
        [(input-port? inp)
         (let-values ([(cipher) (init ci key iv)]
                      [(rd wr) (make-pipe)])
           (thread (lambda () 
                     (cipher-pump cipher inp wr)
                     (close-output-port wr)))
           rd)]))

(define (*crypt-pump who init ci key iv inp outp)
  (let ([inp (if (bytes? inp) (open-input-bytes inp) inp)])
    (cipher-pump (init ci key iv) inp outp)))

(define (-make-cipher-pipe-fun who init)
  (case-lambda
    [(ci key iv)
     (*crypt-pipe who init ci key iv)]
    [(ci key iv inp)
     (*crypt-input who init ci key iv inp)]
    [(ci key iv inp outp)
     (*crypt-pump who init ci key iv inp outp)]))

(define encrypt (-make-cipher-pipe-fun 'encrypt make-encrypt-cipher-ctx))
(define decrypt (-make-cipher-pipe-fun 'decrypt make-decrypt-cipher-ctx))

(define (encrypt->bytes ci key iv inp)
  (let ([enc-inp (*crypt-input 'encrypt->bytes make-encrypt-cipher-ctx ci key iv inp)])
    (port->bytes enc-inp)))

(define (decrypt->bytes ci key iv inp)
  (let ([dec-inp (*crypt-input 'decrypt->bytes make-decrypt-cipher-ctx ci key iv inp)])
    (port->bytes dec-inp)))

;; ----

(define (generate-cipher-key+iv ci)
  (send ci generate-key+iv))
