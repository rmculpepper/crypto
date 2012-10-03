#lang racket/base
(require racket/class
         racket/system
         racket/string
         racket/port
         "../common/interfaces.rkt"
         "../common/common.rkt"
         (only-in "../ssl/util.rkt" hex unhex))
(provide (all-defined-out))

(define (random-bytes size)
  (let ([bs (make-bytes size)])
    (for ([i (in-range size)])
      (bytes-set! bs i (random 255)))
    bs))

;; when it goes through a text file, etc
(define (random-alpha-bytes size)
  (let ([bs (make-bytes size)])
    (for ([i (in-range size)])
      (bytes-set! bs (+ (random 26) (char->integer #\a))))
    bs))

;; ============================================================

(define process-handler%
  (class base-ctx%
    (super-new)

    (field [sp #f]
           [spout #f]
           [spin #f]
           [sperr #f])

    (set!-values (sp spout spin sperr)
      (apply subprocess #f #f #f "/usr/bin/openssl" (get-openssl-args)))

    (eprintf "** ~a\n" (string-join (cons "/usr/bin/openssl" (get-openssl-args)) " "))
    
    (abstract get-openssl-args)

    (define/public (write! who buf start end)
      (write-bytes buf spin start end)
      (flush-output spin)
      (void))

    (define/public (close/read who)
      (close-output-port spin)
      (sync sp)
      (let ([err (port->string sperr)])
        (unless (zero? (string-length err))
          (eprintf "err: ~e\n" err)))
      (close-input-port sperr)
      (begin0 (port->bytes spout)
        (close-input-port spout)))
    ))

;; ============================================================

(define digest-impl%
  (class* object% (digest-impl<%>)
    (init-field name
                size)
    (super-new)

    (define/public (get-name) name)
    (define/public (get-size) size)

    (define/public (new-ctx)
      (new digest-ctx% (impl this)))

    (define/public (get-hmac-impl who)
      (error who "not implemented"))
    (define/public (hmac-buffer who key buf start end) #f)
    (define/public (generate-hmac-key)
      (random-bytes size))
    ))

(define digest-ctx%
  (class* process-handler% (digest-ctx<%>)
    (inherit-field impl)
    (inherit write! close/read)
    (super-new)

    (define/override (get-openssl-args)
      (list "dgst" (format "-~a" (send impl get-name)) "-binary"))

    (define/public (update! who buf start end)
      (write! who buf start end))

    (define/public (final! who buf start end)
      (let ([md (close/read who)])
        (bytes-copy! buf start md)
        (bytes-length md)))

    (define/public (copy who)
      (error who "not implemented"))
    ))

(define (di name size) (new digest-impl% (name name) (size size)))

(define digest:md5 (di "md5" 16))
(define digest:sha1 (di "sha1" 20))

;; ============================================================

(define cipher-impl%
  (class* object% (cipher-impl<%>)
    (init-field name keylen blocklen [ivlen blocklen])
    (super-new)

    (define/public (get-name) name)
    (define/public (get-key-size) keylen)
    (define/public (get-block-size) blocklen)
    (define/public (get-iv-size) ivlen)

    (define/public (new-ctx who key iv enc? pad?)
      (new cipher-ctx% (impl this) (key key) (iv iv) (enc? enc?) (pad? pad?)))

    (define/public (generate-key+iv)
      (values (random-bytes keylen)
              (and ivlen (random-bytes ivlen))))
    ))

(define cipher-ctx%
  (class* process-handler% (cipher-ctx<%>)
    (init-field key iv enc? pad?)
    (inherit-field impl spout)
    (inherit write! close/read)
    (super-new)

    (define/override (get-openssl-args)
      (list* "enc"
             (format "-~a" (send impl get-name))
             (if enc? "-e" "-d")
             "-bufsize" "1"
             "-K" (bytes->string/latin-1 (hex key))
             (append (if pad? '() '("-nopad"))
                     (if iv (list "-iv" (bytes->string/latin-1 (hex iv))) '()))))

    #|
    The openssl enc command doesn't write *any* data until it's been sent
    everything. (Or so it seems... need to investigate -bufsize more.)
    So the normal update! interface doesn't work at all... it just happens to
    work currently on short data because the implementation of final! below
    doesn't respect the end arg and cipher-pump uses larger buffers.

    This probably the current update!/final! interface is bad and should be
    replaced. Perhaps update!/final! should allocate bytes; perhaps should
    take an output port arg. Or allow some implementation choice.
    |#

    (define/public (update! who inbuf instart inend outbuf outstart outend)
      (write! who inbuf instart inend)
      (let ([n (read-bytes-avail!* outbuf spout outstart outend)])
        (eprintf "update! got ~s bytes\n" n)
        n))

    (define/public (final! who buf start end)
      (let ([tail (close/read who)])
        (eprintf "final! got ~e\n" tail)
        (bytes-copy! buf start tail)
        (bytes-length tail)))
    ))

(define (ci name keylen blocklen ivlen)
  (new cipher-impl% (name name) (keylen keylen) (blocklen blocklen) (ivlen ivlen)))

(define aes-128-cbc (ci "aes-128-cbc" 16 16 16))
(define aes-128-ecb (ci "aes-128-ecb" 16 16 #f))

(define key16 #"keyAkeyBkeyCkeyD")
(define iv16  #"ivIVivIVivIVivIV")
(define data  #"hello goodbye")

(require "../common/digest.rkt"
         "../common/cipher.rkt")
(provide (all-from-out "../common/digest.rkt")
         (all-from-out "../common/cipher.rkt"))
