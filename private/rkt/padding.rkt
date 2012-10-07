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
(provide (all-defined-out))

;; References:
;; http://en.wikipedia.org/wiki/Padding_%28cryptography%29
;; http://msdn.microsoft.com/en-us/library/system.security.cryptography.paddingmode.aspx
;; http://tools.ietf.org/html/rfc5246#page-22
;; http://tools.ietf.org/html/rfc5652#section-6.3

;; FIXME: add checks
;;  - pos < end
;;  - pad-byte < 256 (when applicable)

;; pad-bytes!/X : bytes nat nat -> void
;; unpad-bytes/X : bytes nat nat -> nat/#f
;;   where result nat is start of padding, result #f means padding ill-formed

(define (pad-bytes!/ansix923 bs pos [end (bytes-length bs)])
  ;; Zeros, then pad-length for final byte
  (let* ([pad-byte (- end pos)])
    (for ([i (in-range pos (sub1 end))])
      (bytes-set! buf i 0))
    (bytes-set! buf (sub1 end) pad-byte)))

(define (unpad-bytes/ansix923 bs [start 0] [end (bytes-length bs)])
  (let* ([pad-length (bytes-ref bs (sub1 end))]
         [pad-start (- end pad-length)])
    (and (>= pad-start start)
         (for/and ([i (in-range pad-start (sub1 end))])
           (= (bytes-ref bs i) #x00))
         pad-start)))

(define (pad-bytes!/pkcs7 bs pos [end (bytes-length bs)])
  ;; Fill with pad-length
  (let* ([pad-byte (- end pos)])
    (for ([i (in-range pos end)])
      (bytes-set! buf i pad-byte))))

(define (unpad-bytes/pkcs7 bs [start 0] [end (bytes-length bs)])
  (let* ([pad-length (bytes-ref bs (sub1 end))]
         [pad-start (- end pad-length)])
    (and (>= pad-start start)
         (for/and ([i (in-range pad-start end)])
           (= (bytes-ref bs i) pad-length))
         pad-start)))

;; IIUC, PKCS5 padding is same as PKCS7 padding except for 64-bit blocks only.
(define (pad-bytes!/pkcs5 bs pos [end (bytes-length bs)])
  (pad-bytes!/pkcs7 bs pos end))
(define (unpad-bytes/pkcs5 bs [start 0] [end (bytes-length bs)])
  (unpad-bytes/pkcs7 bs start end))

(define (pad-bytes!/iso/iec-7816-4 bs pos [end (bytes-length bs)])
  ;; One byte of #x80, then fill with zeroes
  (bytes-set! buf pos #x80)
  (for ([i (in-range (add1 pos) end)])
    (bytes-set! buf i #x00)))

(define (unpad-bytes/iso/iec-7816-4 bs [start 0] [end (bytes-length bs)])
  (let loop ([i (sub1 end)])
    (and (>= i start)
         (case (bytes-ref bs i)
           ((#x00) (loop (sub1 i)))
           ((#x80) i)
           (else #f)))))

(define (pad-bytes!/tls bs pos [end (bytes-length bs)])
  ;; Fill with (pad-length - 1)--because a record contains a separate final
  ;; pad-length field that is not considered part of padding.
  ;; So technically this function adds both padding and a pad-length field.
  (let* ([pad-byte (sub1 (- end pos))])
    (for ([i (in-range pos end)])
      (bytes-set! buf i pad-byte))))

(define (unpad-bytes/tls bs [start 0] [end (bytes-length bs)])
  (let* ([pad-byte (add1 (bytes-ref bs (sub1 end)))]
         [pad-start (- end (add1 pad-byte))])
    (and (>= pad-start start)
         (for/and ([i (in-range pad-start end)])
           (= (bytes-ref bs i) pad-byte))
         pad-start)))
