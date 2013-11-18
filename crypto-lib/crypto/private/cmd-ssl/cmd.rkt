;; Copyright 2012 Ryan Culpepper
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
         racket/match
         racket/system
         racket/string
         racket/dict
         racket/port
         racket/file
         "../common/catalog.rkt"
         "../common/interfaces.rkt"
         "../common/common.rkt"
         (only-in "../libcrypto/util.rkt" hex unhex))
(provide (all-defined-out))

;; ============================================================

(define process-handler%
  (class ctx-base%
    (super-new)

    (field [sp #f]
           [spout #f]
           [spin #f]
           [sperr #f])

    (define args
      (for/list ([arg (get-openssl-args)] #:when arg)
        (format "~a" arg)))

    (set!-values (sp spout spin sperr)
      (apply subprocess #f #f #f "/usr/bin/openssl" args))

    (when #f
      (eprintf "** ~a\n" (string-join (cons "/usr/bin/openssl" args) " ")))

    (abstract get-openssl-args)

    (define/public (write! who buf start end)
      (write-bytes buf spin start end)
      (flush-output spin)
      (void))

    (define/public (close/read who)
      (close-output-port spin)
      (sync sp)
      (unless (zero? (subprocess-status sp))
        (let ([err (port->string sperr)])
          (close-input-port sperr)
          (close-input-port spout)
          (error who "subprocess failed: ~a" err)))
      (close-input-port sperr)
      (begin0 (port->bytes spout)
        (close-input-port spout)))
    ))

(define process/args%
  (class process-handler%
    (init-field args)
    (super-new)
    (define/override (get-openssl-args) args)))

(define (openssl #:in [send-to-in #f] . args)
  (let ([p (new process/args% (impl #f) (args args))])
    (when send-to-in
      (send p write! 'openssl send-to-in 0 (bytes-length send-to-in)))
    (send p close/read 'openssl)))

(define-syntax-rule (with-tmp-files ([id contents] ...) . body)
  (let ([id (make-temporary-file)] ...)
    (with-output-to-file id #:exists 'truncate (lambda () (write-bytes contents))) ...
    (call-with-continuation-barrier
     (lambda ()
       (dynamic-wind void
                     (lambda () . body)
                     (lambda () (delete-file id) ... (void)))))))

;; ============================================================

(define digest-impl%
  (class* impl-base% (digest-impl<%>)
    (init-field cmd
                size
                block-size)
    (super-new)

    (define/public (get-size) size)
    (define/public (get-block-size) block-size)

    (define/public (new-ctx)
      (new digest-ctx% (impl this)))
    (define/public (get-hmac-impl who)
      (new hmac-impl% (digest this)))

    ;; ----

    (define/public (can-digest-buffer!?) #t)
    (define/public (digest-buffer! who buf start end outbuf outstart)
      (let ([md (openssl "dgst" (format "-~a" cmd) "-binary"
                         #:in (subbytes buf start end))])
        (bytes-copy! outbuf outstart md)
        (bytes-length md)))

    (define/public (can-hmac-buffer!?) #t)
    (define/public (hmac-buffer! who key buf start end outbuf outstart)
      (let ([md (openssl "dgst" (format "-~a" cmd) "-binary"
                         "-hmac" key #:in (subbytes buf start end))])
        (bytes-copy! outbuf outstart md)
        (bytes-length md)))
    ))

(define hmac-impl%
  (class* object% (hmac-impl<%>)
    (init-field digest)
    (super-new)

    (define/public (get-spec) `(hmac ,(send digest get-spec)))
    (define/public (get-factory) (send digest get-factory))
    (define/public (get-digest) digest)
    (define/public (new-ctx who key)
      ;; There seems to be no way to pass HMAC keys containing embedded NUL bytes :(
      (unless (bytes-no-nuls? key)
        (error who "key must not contain NUL byte, got: ~e" key))
      (new digest-ctx% (impl digest) (hmac-key key)))
    ))

(define digest-ctx%
  (class* ctx-base% (digest-ctx<%>)
    (init-field [hmac-key #f])
    (inherit-field impl)
    (super-new)

    (define stored-content (open-output-bytes))

    (define/public (get-content who reset?)
      (begin0 (get-output-bytes stored-content)
        (when reset? (set! stored-content #f))))

    (define/public (update who buf start end)
      (void (write-bytes buf stored-content start end)))

    (define/public (final! who buf start end)
      (let* ([content (get-content who #t)])
        (if hmac-key
            (send impl hmac-buffer! who hmac-key
                  content 0 (bytes-length content) buf start)
            (send impl digest-buffer! who
                  content 0 (bytes-length content) buf start))))

    (define/public (copy who)
      (let* ([content-so-far (get-content who #f)]
             [dg2 (new digest-ctx% (impl impl) (hmac-key hmac-key))])
        (send dg2 update! who content-so-far 0 (bytes-length content-so-far))
        dg2))
    ))

;; ============================================================

(define cipher-impl%
  (class* impl-base% (cipher-impl<%>)
    (init-field blocklen ivlen cmd)
    (inherit-field spec)
    (super-new)

    (define/public (get-block-size) blocklen)
    (define/public (get-iv-size) ivlen)
    (define/public (get-cmd) cmd)

    (define/public (new-ctx who key iv enc? pad?)
      (let ([pad? (and pad? (cipher-spec-uses-padding? spec))])
        (new cipher-ctx% (impl this) (key key) (iv iv) (enc? enc?) (pad? pad?))))
    ))

(define cipher-ctx%
  (class* process-handler% (cipher-ctx<%>)
    (init-field key iv enc? pad?)
    (inherit-field impl spout)
    (inherit write! close/read)
    (super-new)

    (define/override (get-openssl-args)
      (list* "enc"
             (format "-~a" (send impl get-cmd))
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
        n))

    (define/public (final! who buf start end)
      (let ([tail (close/read who)])
        (bytes-copy! buf start tail)
        (bytes-length tail)))
    ))

;; ============================================================

#|
*** Don't ever use this code with sensitive keys. ***

Since most openssl commands take keys as filenames, we write keys to temp files.

{read,write}-key uses PEM format instead of DER
FIXME: check again whether DER available in older versions
|#


(define pk-impl%
  (class* impl-base% (pk-impl<%>)
    (init-field sys)
    (super-new)

    (define/public (get-name) sys)

    (define/public (read-key who key pub/priv fmt)
      (new pk-key% (impl this) (key key) (private? (eq? pub/priv 'private))))
    (define/public (read-params who buf fmt)
      (error who "unimplemented"))

    (define/public (generate-key who args)
      (let* ([key
              (case sys
                [(rsa) (openssl "genrsa" (car args))]
                [(dsa)
                 (let ([params (openssl "dsaparam" (car args))])
                   (with-tmp-files ([paramfile params])
                     (openssl "gendsa" paramfile)))])])
        (new pk-key% (impl this) (key key) (private? #t))))
    (define/public (generate-params who args)
      (error who "unimplemented"))

    (define/public (can-sign?) #t)
    (define/public (can-encrypt?) (and (memq sys '(rsa)) #t))
    ))

(define pk-key%
  (class* ctx-base% (pk-key<%>)
    (init-field key private?)
    (inherit-field impl)
    (super-new)

    (define/public (is-private?) private?)

    (define/public (get-public-key who)
      (error who "unimplemented"))
    (define/public (get-params who)
      (error who "unimplemented"))

    (define/public (write-key who pub/priv fmt)
      (let ([want-private? (eq? pub/priv 'private)])
        (cond [(and private? want-private?) key]
              [(and private? (not want-private?))
               (openssl (send impl get-name) "-pubout" #:in key)]
              [(and (not private?) want-private?)
               (error who "only public key component is available")]
              [(and (not private?) (not want-private?)) key])))

    (define/public (equal-to-key? other)
      (equal? (write-key 'equal-to-key? #t)
              (send other write-key 'equal-to-key? #t)))

    #|
    ;; New:
    Not sure if "openssl pkeyutl" supports signing predigested data.

    ;; Old comments:
    Cannot sign an existing digest-context using command line, so we make
    digest store all data. Again, suggests a more flexible interface might be good.
    |#

    #|
    (define/public (sign who digest di)
      (unless private? (error who "cannot sign with public key"))
      (with-tmp-files ([keyfile key])
        (let* ([signature
                (openssl "pkeyutl" "-sign" "-binary"
                         "-sign" keyfile
                         #:in (send dg get-content who #f))])
          (bytes-copy! buf start signature)
          (bytes-length signature))))

    (define/public (verify who dg buf start end)
      (with-tmp-files ([keyfile key]
                       [sigfile (subbytes buf start end)])
        (let* ([impl (send dg get-impl)]
               [result
                (openssl "dgst" (format "-~a" (send impl get-name))
                         (if private? "-prverify" "-verify") keyfile
                         "-signature" sigfile
                         #:in (send dg get-content who #f))])
          (cond [(regexp-match? #rx#"OK" result)
                 #t]
                [(regexp-match #rx#"Fail" result)
                 #f]
                [else
                 (error who "internal error; openssl returned unexpected result: ~e"
                        result)]))))

    (define/public (encrypt/decrypt who encrypt? want-public? inbuf instart inend)
      (case (get-field sys impl)
        ((dsa)
         (error who "operation not supported for DSA"))
        ((rsa)
         (unless (or want-public? private?)
           (error who "not a private key"))
         (with-tmp-files ([keyfile key])
           (let ([result
                  (openssl "rsautl"
                           "-inkey" keyfile
                          (and want-public? "-pubin")
                           (if encrypt? "-encrypt" "-decrypt")
                           #:in (subbytes inbuf instart inend))])
             result)))))
    |#
    ))

;; ============================================================

#|
(require "../common/digest.rkt"
         "../common/cipher.rkt"
         "../common/pkey.rkt")
(provide (all-from-out "../common/digest.rkt")
         (all-from-out "../common/cipher.rkt")
         (all-from-out "../common/pkey.rkt"))

(define key16 #"keyAkeyBkeyCkeyD")
(define key00 #"keyAkey\0keyCkeyD")
(define iv16  #"ivIVivIVivIVivIV")
(define data  #"hello goodbye")
|#

(define (di spec cmd)
  (match (hash-ref known-digests spec #f)
    [(list size block-size)
     (new digest-impl%
          (spec spec)
          (factory cmdssl-factory)
          (cmd cmd)
          (size size)
          (block-size block-size))]))

(define digests
  '([md5 "md5"]
    [ripemd160 "rmd160"]
    [sha1 "sha1"]
    [sha224 "sha224"]
    [sha256 "sha256"]
    [sha384 "sha384"]
    [sha512 "sha512"]))

(define (ci spec cmd/s)
  (if (list? cmd/s)
      (new multikeylen-cipher-impl%
           (spec spec)
           (factory cmdssl-factory)
           (impls (for/list ([len+cmd cmd/s])
                    (cons (car len+cmd)
                          (ci spec (cdr len+cmd))))))
      (new cipher-impl%
           (spec spec)
           (factory cmdssl-factory)
           (cmd cmd/s)
           (blocklen (cipher-spec-block-size spec))
           (ivlen (cipher-spec-iv-size spec)))))

(define ciphers
  '([aes (ecb cbc) (128 192 256)]))

(define pkey:rsa 'fixme-rsa)
(define pkey:dsa 'fixme-dsa)

#|
(define pkey:rsa (new pkey-impl% (sys 'rsa)))
(define pkey:dsa (new pkey-impl% (sys 'dsa)))
|#

;; ============================================================

(define cmdssl-factory%
  (class* factory-base% (factory<%>)
    (super-new)

    (define/override (get-digest* name)
      (cond [(assq name digests)
             => (lambda (entry)
                  (di name (cadr entry)))]
            [else #f]))

    (define/override (get-cipher* spec)
      (match spec
        [(list name mode)
         (cond [(assq name ciphers)
                => (lambda (entry)
                     (match entry
                       [(list _ modes keylens)
                        (and (memq mode modes)
                             (ci spec (for/list ([keylen keylens])
                                        (cons (quotient keylen 8)
                                              (format "~a-~a-~a" name keylen mode)))))]
                       [_ #f]))]
               [else #f])]))

    (define/override (get-pkey name)
      (case name
        ((rsa) pkey:rsa)
        ((dsa) pkey:dsa)
        (else #f)))
    ))

(define cmdssl-factory (new cmdssl-factory%))
