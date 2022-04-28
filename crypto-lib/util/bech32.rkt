;; Copyright 2022 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/contract
         racket/match)
(provide bech32-string?
         (contract-out
          #:unprotected-submodule unchecked
          [bech32-encode (-> bech32-hrp-string? bytes? string?)]
          [bech32-decode (-> bech32-string? (list/c string? bytes?))]))

;; bech32 codec
;; Reference:
;; - https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki

;; A Bech32 string is at most 90 characters long and consists of
;; - HRP (human-readable part): 1-83 US-ASCII characters in [33-126]
;; - separator: a "1" char (HRP may contain "1" chars, but data cannot,
;;     so separator is last "1" char in string)
;; - data part: at least 6 characters in (alphanumeric except "1bio")

;; bech32-string? : Any -> Boolean
(define (bech32-string? v)
  ;; (define bech32-rx #px#"^[\x21-\x7E]{1,83}[1][02-9AC-HJ-NP-Zac-hj-np-z]{6,}$")
  (define lower-rx #px"^[!-@\\[-~]+[1][02-9ac-hj-np-z]{6,}$")
  (define upper-rx #px"^[!-`{-~]+[1][02-9AC-HJ-NP-Z]{6,}$")
  (and (string? v)
       (<= (string-length v) 90)
       (or (regexp-match? lower-rx v)
           (regexp-match? upper-rx v))))

;; bech32-hrp-string? : Any -> Boolean
(define (bech32-hrp-string? v)
  (define bech32-hrp-rx #px"^[\x21-\x7E]{1,83}$")
  (and (string? v)
       (<= 1 (string-length v) 83)
       (regexp-match? bech32-hrp-rx v)))

;; bech32-encode : String Bytes -> String
(define (bech32-encode hrp-s data8)
  (define hrp (string->bytes/latin-1 (string-downcase hrp-s)))
  (let* ([data5len (quotient (+ (* (bytes-length data8) 8) 7) 5)]
         [enc-len (+ (bytes-length hrp) 1 data5len 6)])
    (unless (<= (+ (bytes-length hrp) 1 data5len 6) 90)
      (error 'bech32-encode "encoded string longer than 90 characters\n  length: ~s" enc-len)))
  (define data5 (convert-bits data8 8 5 #t))
  (define cs (create-checksum hrp data5))
  (begin (encode! data5) (encode! cs))
  (bytes->string/latin-1 (bytes-append hrp #"1" data5 cs)))

;; bech32-decode : String -> (list String Bytes)
(define (bech32-decode s)
  (define bs (string->bytes/latin-1 (string-downcase s)))
  (match (regexp-match #px#"^(.+)1([^1]*)([^1]{6})$" bs)
    [(list _ hrp data5 cs)
     (begin (decode! data5) (decode! cs))
     (unless (verify-checksum hrp (bytes-append data5 cs))
       (error 'bech32-decode "invalid checksum"))
     (list (bytes->string/latin-1 hrp) (convert-bits data5 5 8 #f))]
    [_ (error 'bech32-decode "decoding failed")]))

;; ----------------------------------------

(define enc-data #"qpzry9x8gf2tvdw0s3jn54khce6mua7l")
(define dec-data (make-bytes 128 0))
(for ([b (in-bytes enc-data)] [i (in-naturals)])
  (bytes-set! dec-data b i)
  (bytes-set! dec-data (+ b (- (char->integer #\A) (char->integer #\a))) i))

(define (encode! bs)
  (for ([b (in-bytes bs)] [i (in-naturals)])
    (bytes-set! bs i (bytes-ref enc-data b))))
(define (decode! bs)
  (for ([b (in-bytes bs)] [i (in-naturals)])
    (bytes-set! bs i (bytes-ref dec-data b))))

;; convert-bits : Bytes Nat[1..8] Nat[1..8] Boolean -> Bytes
(define (convert-bits in inbits outbits pad?)
  (define out (open-output-bytes))
  (define LIM (expt 2 inbits))
  (define (emit acc accbits [final? #f])
    (cond [(zero? accbits)
           (values acc accbits)]
          [(>= accbits outbits)
           (define lo (- accbits outbits))
           (define n (bitwise-bit-field acc lo accbits))
           (write-byte n out)
           (emit (bitwise-bit-field acc 0 lo) lo final?)]
          [final?
           (cond [pad?
                  (define pad (- outbits accbits))
                  (write-byte (arithmetic-shift acc pad) out)
                  (void)]
                 [else
                  (unless (zero? acc)
                    (error 'convert-bits "bits left over: ~s" (list acc accbits)))
                  (void)])]
          [else (values acc accbits)]))
  (for/fold ([acc 0] [accbits 0] #:result (emit acc accbits #t))
            ([in-b (in-bytes in)])
    (unless (< in-b LIM) (error 'convert-bits "bad byte value: ~e" in-b))
    (emit (+ (arithmetic-shift acc inbits) in-b)
          (+ accbits inbits)))
  (get-output-bytes out))

(define (polymod bs [start-chk 1])
  (define GEN '(#x3b6a57b2 #x26508e6d #x1ea119fa #x3d4233dd #x2a1462b3))
  (for/fold ([chk start-chk])
            ([v (in-bytes bs)])
    (define b (arithmetic-shift chk -25))
    (define chk* (bitwise-xor
                  (arithmetic-shift (bitwise-and chk #x1ffffff) 5)
                  v))
    (for/fold ([chk chk*])
              ([i (in-range 5)] [GENi (in-list GEN)])
      (bitwise-xor chk (if (bitwise-bit-set? b i) GENi 0)))))

(define (hrp-expand hrp)
  (bytes-append (apply bytes (for/list ([b (in-bytes hrp)]) (arithmetic-shift b -5)))
                (bytes 0)
                (apply bytes (for/list ([b (in-bytes hrp)]) (bitwise-and b 31)))))

(define (verify-checksum hrp data+cs [start-chk 1])
  (define hrp-chk (polymod (hrp-expand hrp) start-chk))
  (= 1 (polymod data+cs hrp-chk)))

(define (create-checksum hrp data [start-chk 1])
  (define hrp-chk (polymod (hrp-expand hrp) start-chk))
  (define data-chk (polymod data hrp-chk))
  (define chk (bitwise-xor 1 (polymod (make-bytes 6 0) data-chk)))
  (define rcs (for/list ([i (in-range 6)]) (bitwise-bit-field chk (* 5 i) (+ 5 (* 5 i)))))
  (apply bytes (reverse rcs)))
