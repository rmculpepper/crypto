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
(provide hkdf
         concat-kdf
         ans-x9.63-kdf
         sp800-108-counter-kdf
         sp800-108-feedback-kdf
         sp800-108-double-pipeline-kdf)

;; General references:
;; - https://tools.ietf.org/html/draft-irtf-cfrg-kdf-uses-00
;; - https://web.archive.org/web/20160322090517/https://www.di-mgt.com.au/cryptoKDFs.html#ISO18033
;; - ISO 18033-2: https://shoup.net/iso/std6.pdf (KDF1, KDF2, but endianness?!)

;; KDF groups
;; - concatmap(secret counter info)
;;   - ANS X9.42 (2003), ANS X9.63 (2001)
;; - concatmap(counter secret info)
;;   - NIST 800-56 One-Step
;; - extract-then-expand
;;   - HKDF

;; PKCS#1 (https://tools.ietf.org/html/rfc3447) defines MGF1 as
;; concatmap(secret counter), but starting at 0.

(define (nat->be-bytes n size)
  (integer->integer-bytes n size #f #t))
(define (nat->le-bytes n size)
  (integer->integer-bytes n size #f #f))

;; utility for concatenating independent blocks
(define (par/concat/trim len init-counter f)
  (define buf (make-bytes len 0))
  (let loop ([counter init-counter] [start 0])
    (when (< start len)
      (define next (f counter))
      (define next-len (bytes-length next))
      (bytes-copy! buf start next 0 (min next-len (- len start)))
      (loop (add1 counter) (+ start next-len))))
  buf)

;; utility for concatenating sequential/feedback blocks
(define (seq/concat/trim len init-counter init-acc f)
  (define buf (make-bytes len 0))
  (let loop ([counter init-counter] [acc init-acc] [start 0])
    (when (< start len)
      (define-values (next next-acc) (f counter acc))
      (define next-len (bytes-length next))
      (bytes-copy! buf start next 0 (min next-len (- len start)))
      (loop (add1 counter) next-acc (+ start next-len))))
  buf)


;; ============================================================
;; HKDF

;; Reference: https://tools.ietf.org/html/rfc5869

;; Note:
;; - default salt is (make-bytes hlen 0)
;; - default info is #""
;; - len <= 255*hlen

(define (hkdf-extract hmac-h salt ikm)
  (hmac-h salt ikm))

(define (hkdf-expand hmac-h info len prk)
  (define (block counter prev)
    (define K (hmac-h prk (bytes-append prev info (bytes counter))))
    (values K K))
  (seq/concat/trim len 1 #"" block))

(define (hkdf hmac-h salt info len ikm)
  (define prk (hkdf-extract hmac-h salt ikm))
  (hkdf-expand hmac-h info len prk))


;; ============================================================
;; NIST SP 800-56C Rev. 1 (2018)

;; Reference:
;; - https://csrc.nist.gov/publications/detail/sp/800-56c/rev-1/final
;; - aka "Single-step KDF" in NIST SP 800-56A Rev. 2 (2013, withdrawn 2018)
;;   (https://csrc.nist.gov/publications/detail/sp/800-56a/rev-2/archive/2013-06-05)
;; - aka "Concatentation KDF" in NIST SP 800-56A Revised (2007, withdrawn 2013)
;;   (https://csrc.nist.gov/publications/detail/sp/800-56a/revised/archive/2007-03-14)

;; One-step KDF
;; H is either a Hash or HMAC-Hash or a KMAC

(define (concat-kdf H info len secret)
  (define (block counter)
    (H (bytes-append (nat->be-bytes counter 4) secret info)))
  (par/concat/trim len 1 block))

;; Two-step KDF (ie, extract-then-expand)
;; Vague. Just use HKDF (an approved instance of these guidelines).


;; ============================================================
;; ANS X9.63 KDF

;; Reference:
;; - SEC-1 v1.9 (http://www.secg.org/sec1-v2.pdf)
;; - NIST SP 800-135 (https://csrc.nist.gov/publications/detail/sp/800-135/rev-1/final)

(define (ans-x9.63-kdf H info len secret)
  (define (block counter)
    (H (bytes-append secret (nat->be-bytes counter 4) info)))
  (par/concat/trim len 1 block))


;; ============================================================
;; NIST 800-108: Recommendation for Key Derivation Using Pseudorandom
;; Functions (2009) (https://csrc.nist.gov/publications/detail/sp/800-108/final)

;; This implementation removes several degrees of freedom from the "standard":
;; - Endianness not specified. Assume big-endian.
;; - Length of integers (counter and length) fixed to 4 bytes.
;; - Position of counter fixed to standard position.
;; - Use single `info` parameter for fixed data.
;;   info = label || #x00 || context || encode(L)

;; A PRF is (Seed Bytes -> Bytes), for example HMAC-hash.

(define (sp800-108-counter-kdf prf info len secret)
  (define (block counter)
    (prf secret (bytes-append (nat->be-bytes counter 4) info)))
  (par/concat/trim len 1 block))

(define (sp800-108-feedback-kdf prf ctr? info len iv secret)
  (define (block counter prev)
    (define K (prf secret (bytes-append prev (if ctr? (nat->be-bytes counter 4) #"") info)))
    (values K K))
  (seq/concat/trim len 1 iv block))

(define (sp800-108-double-pipeline-kdf prf ctr? info len secret)
  (define (block counter prev-A)
    (define A (prf secret prev-A))
    (define K (prf secret (bytes-append A (if ctr? (nat->be-bytes counter 4) #"") info)))
    (values K A))
  (define iv info)
  (seq/concat/trim len 1 iv block))
