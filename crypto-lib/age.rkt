#lang racket/base
(require racket/match
         racket/class
         racket/string
         crypto
         crypto/util/bech32
         binaryio/integer
         base64
         scramble/regexp
         syntax/readerr)
(provide (all-defined-out))

;; age -- tool for file encryption

;; References:
;; - https://age-encryption.org/v1
;; - https://github.com/C2SP/C2SP/blob/main/age.md

;; An Identity is one of
;; - Bytes                    -- a passphrase
;; - PrivateKey

;; A Recipient is one of
;; - (list 'scrypt Bytes)     -- a passphrase
;; - PublicKey

(define CHUNK-SIZE (expt 2 16))
(define ENC-CHUNK-SIZE (+ CHUNK-SIZE (cipher-default-auth-size '(chacha20-poly1305 stream))))

(define age%
  (class object%
    (super-new)

    (define cipher (get-cipher '(chacha20-poly1305 stream)))
    (define hkdfi (get-kdf '(hkdf sha256)))
    (define mac-di (get-digest 'sha256))
    (define scrypt (get-kdf 'scrypt))

    (define/private (get-mac-key file-key)
      (kdf hkdfi file-key #f '((info #"header") (key-size 32))))
    (define/private (get-payload-key file-key file-nonce)
      (kdf hkdfi file-key file-nonce '((info #"payload") (key-size 32))))
    (define/private (get-x25519-recip-key shared-secret salt)
      (define info #"age-encryption.org/v1/X25519")
      (kdf hkdfi shared-secret salt `((info ,info) (key-size 32))))
    (define/private (get-scrypt-recip-key pass salt0 ln)
      (define N (expt 2 ln))
      (define salt (bytes-append #"age-encryption.org/v1/scrypt" salt0))
      (kdf scrypt pass salt `((N ,N) (r 8) (p 1) (key-size 32))))

    (define/private (get-header-mac mac-key header)
      (hmac mac-di mac-key header))

    (define/private (wrap-file-key recip-key file-key)
      (define iv (make-bytes 12 0))
      (encrypt cipher recip-key iv file-key))

    (define/private (unwrap-file-key recip-key enc-file-key)
      (define iv (make-bytes 12 0))
      (with-handlers ([exn:fail? (lambda (e) #f)])
        (decrypt cipher recip-key iv enc-file-key)))

    ;; ----------------------------------------

    (define/public (age-encrypt recips in out)
      (define file-key (crypto-random-bytes 16))
      (define file-nonce (crypto-random-bytes 16))
      (define mac-key (get-mac-key file-key))
      (define payload-key (get-payload-key file-key file-nonce))
      ;; ---- Header ----
      (let ([header-out (open-output-bytes)])
        (fprintf header-out "age-encryption.org/v1\n")
        (for ([recip (in-list recips)])
          (write-recipient-stanza 'age-encrypt header-out file-key recip))
        (fprintf header-out "---")
        (define header-bytes (get-output-bytes header-out))
        (define header-mac (get-header-mac mac-key header-bytes))
        (write-bytes header-bytes out)
        (fprintf out " ~a\n" (base64-encode header-mac)))
      ;; ---- Payload ----
      (write-bytes file-nonce out)
      (let loop ([counter 0])
        (define-values (chunk final?) (read-chunk in))
        (define enc-chunk (encrypt-chunk payload-key counter final? chunk))
        (write-bytes enc-chunk out)
        (unless final? (loop (add1 counter))))
      (void))

    (define/private (write-recipient-stanza who out file-key recip)
      (fprintf out "-> ")
      (match recip
        [(list 'scrypt (? bytes? pass))
         (define ln 18) ;; FIXME: make parameter
         (define salt0 (crypto-random-bytes 16))
         (define recip-key (get-scrypt-recip-key pass salt0 ln))
         (define enc-file-key (wrap-file-key recip-key file-key))
         (fprintf out "scrypt ~a ~a\n" (base64-encode salt0) ln)
         (fprintf out "~a\n" (base64-encode enc-file-key)) ;; < 64 bytes
         (void)]
        [(? pk-key? recip-pk)
         (match (pk-key->datum recip-pk 'rkt-public)
           [(list 'ecx 'public 'x25519 (? bytes? recip-pk-bytes))
            (define eph-sk (generate-private-key (pk-key->parameters recip-pk)))
            (match-define (list 'ecx 'public 'x25519 eph-pk-bytes)
              (pk-key->datum eph-sk 'rkt-public))
            (define salt (bytes-append eph-pk-bytes recip-pk-bytes))
            (define shared-secret (pk-derive-secret eph-sk recip-pk))
            (when (all-zero? shared-secret)
              (error who "X25519 shared secret is zero"))
            (define recip-key (get-x25519-recip-key shared-secret salt))
            (define enc-file-key (wrap-file-key recip-key file-key))
            (fprintf out "X25519 ~a\n" (base64-encode eph-pk-bytes))
            (fprintf out "~a\n" (base64-encode enc-file-key)) ;; < 64 bytes
            (void)]
           [_ (error who "recipient not supported\n  public key: ~e" (send recip-pk about))])]
        [_ (error who "recipient not supported\n  recipient: ~e" recip)]))

    (define/private (read-chunk in)
      (define chunk (read-bytes CHUNK-SIZE in))
      (cond [(eof-object? chunk) (values #"" #t)]
            [else (values chunk (eof-object? (peek-byte in)))]))

    (define/private (encrypt-chunk payload-key counter final? chunk)
      (define nonce (make-chunk-nonce counter final?))
      (encrypt cipher payload-key nonce chunk))

    (define/private (make-chunk-nonce counter final?)
      (define nonce-n (+ (arithmetic-shift counter 8) (if final? #x01 #x00)))
      (integer->bytes nonce-n 12 #f #t))

    ;; ----------------------------------------

    (define/public (age-decrypt idents in out)
      (match-define (header header-bytes mac stanzas) (read-header 'age-decrypt in))
      (define file-key
        (for*/or ([recip-stanza (in-list stanzas)]
                  [ident (in-list idents)])
          (match recip-stanza
            [(stanza "scrypt" (list salt-b64 (regexp #rx"^[0-9]+$" (list ln-s))) enc-file-key-b64)
             (define ln (string->number ln-s))
             (define salt0 (base64-decode salt-b64))
             (match ident
               [(? bytes? pass)
                (define recip-key (get-scrypt-recip-key pass salt0 ln))
                (unwrap-file-key recip-key (base64-decode enc-file-key-b64))]
               [_ #f])]
            [(stanza "X25519" (list eph-pk-b64) enc-file-key-b64)
             (define eph-pk-bytes (base64-decode eph-pk-b64))
             (match (and (private-key? ident) (pk-key->datum ident 'rkt-private))
               [(list 'ecx 'private 'x25519 my-pub-bytes my-priv-bytes)
                (define eph-pk (datum->pk-key (list 'ecx 'public 'x25519 eph-pk-bytes) 'rkt-public))
                (define shared-secret (pk-derive-secret ident eph-pk))
                (cond [(all-zero? shared-secret)
                       #f]
                      [else
                       (define salt (bytes-append eph-pk-bytes my-pub-bytes))
                       (define recip-key (get-x25519-recip-key shared-secret salt))
                       (unwrap-file-key recip-key (base64-decode enc-file-key-b64))])]
               [_ #f])]
            [_ #f])))
      (unless file-key
        (error 'age-decrypt "no identity matched"))
      (define mac-key (get-mac-key file-key))
      (unless (crypto-bytes=? mac (get-header-mac mac-key header-bytes))
        (error 'age-decrypt "invalid MAC"))
      (define file-nonce (read-bytes 16 in))
      (unless (and (bytes? file-nonce) (= (bytes-length file-nonce) 16))
        (error 'age-decrypt "invalid payload: missing or incomplete file nonce"))
      (define payload-key (get-payload-key file-key file-nonce))
      (let loop ([counter 0])
        (define-values (enc-chunk final?) (read-enc-chunk 'age-decrypt in))
        (define nonce (make-chunk-nonce counter final?))
        (write-bytes (decrypt cipher payload-key nonce enc-chunk) out)
        (unless final? (loop (add1 counter)))))

    (define/private (read-enc-chunk who in)
      (define enc-chunk (read-bytes ENC-CHUNK-SIZE in))
      (when (eof-object? enc-chunk)
        (error who "invalid payload: expected encrypted chunk"))
      (values enc-chunk (eof-object? (peek-byte in))))
    ))

(define (all-zero? bs)
  (zero? (for/sum ([b (in-bytes bs)]) b)))

;; ----------------------------------------
;; Parsing headers

(struct header (bytes mac stanzas) #:prefab)
(struct stanza (name args body) #:prefab)

;; header = v1-line 1*stanza end
;; end = "--- " 43base64char LF

(define-RE VCHAR (chars [#x21 #x7E]))
(define-RE base64char (chars (union alpha digit "+/")))
(define-RE LF (chars "\n"))

(define-RE argument (+ VCHAR))
(define-RE arg-line (cat "-> " (report (cat argument (* (cat " " argument)))) LF))
(define-RE full-line (cat (repeat base64char 64) LF))
(define-RE final-line (cat (repeat base64char 0 63) LF))
;; (define-RE stanza (cat arg-line (* full-line) final-line))

(define-RE v1-line "age-encryption.org/v1\n")
(define-RE mac-part (cat " " (report (cat (repeat base64char 43) LF))))

;; read-header : Symbol InputPort -> Header
(define (read-header who in)
  (define LINE-LIMIT 100) ;; FIXME?
  (define (bad msg . args)
    (define-values (line col pos) (port-next-location in))
    (raise-read-error (format "~a: ~a" who (apply format msg args))
                      (object-name in) line col pos #f))
  (define out (open-output-bytes))
  (define (read-rx rx [limit LINE-LIMIT])
    (define r (regexp-try-match rx in 0 limit))
    (begin (when r (write-bytes (car r) out)) r))
  (unless (read-rx (px ^ v1-line))
    (bad "invalid format: bad or missing version line"))
  ;; ----
  (define (read-stanzas)
    (cond [(read-rx #rx"^---")
           null]
          [(read-rx (px ^ arg-line))
           => (match-lambda
                [(list m args-bs)
                 (define args (string-split (bytes->string/latin-1 args-bs) " "))
                 (define body (apply bytes-append (read-stanza-body)))
                 (cons (stanza (car args) (cdr args) body)
                       (read-stanzas))])]
          [else (bad "invalid format: expected end or stanza")]))
  (define (read-stanza-body)
    (cond [(read-rx (px ^ final-line))
           => (match-lambda
                [(list m) (list m)])]
          [(read-rx (px ^ full-line))
           => (match-lambda
                [(list m) (cons m (read-stanza-body))])]
          [else (bad "invalid format: malformed stanza body")]))
  (define stanzas (read-stanzas))
  ;; ----
  (define header-bytes (get-output-bytes out))
  (define mac
    (cond [(read-rx (px ^ mac-part))
           => (match-lambda [(list _ mac-s) (base64-decode mac-s)])]
          [else (bad "expected MAC")]))
  (header header-bytes mac stanzas))

;; ----------------------------------------

(define (age-encrypt recips in)
  (define age (new age%))
  (define out (open-output-bytes))
  (let ([in (if (bytes? in) (open-input-bytes in) in)])
    (send age age-encrypt recips in out))
  (get-output-bytes out))

(define (age-decrypt idents in)
  (define age (new age%))
  (define out (open-output-bytes))
  (let ([in (if (bytes? in) (open-input-bytes in) in)])
    (send age age-decrypt idents in out))
  (get-output-bytes out))

;; pk-key->age-format : PK-Key -> (list (U #f String) String)
(define (pk-key->age-format pk)
  (list (match (and (private-key? pk) (pk-key->datum pk 'rkt-private))
          [(list 'ecx 'private 'x25519 _ priv)
           (string-upcase (bech32-encode "age-secret-key-" priv))]
          [_ #f])
        (match (pk-key->datum pk 'rkt-public)
          [(list 'ecx 'public 'x25519 pub)
           (bech32-encode "age" pub)]
          [_ #f])))
