;; mzcrypto: libcrypto bindings for PLT-scheme
;; error handling
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
         "macros.rkt"
         "libcrypto.rkt")
(provide (all-defined-out))

(define/ffi (ERR_get_error) -> _ulong)
(define/ffi (ERR_peek_last_error) -> _ulong)
(define/ffi (ERR_lib_error_string _ulong) -> _string)
(define/ffi (ERR_func_error_string _ulong) -> _string)
(define/ffi (ERR_reason_error_string _ulong) -> _string)

(define (format-crypto-error e info)
  (let ((errstr 
         (alet* ((le (ERR_lib_error_string e))
                 (fe (ERR_func_error_string e))
                 (re (ERR_reason_error_string e)))
           (format "~a [~a:~a:~a]"
             (ERR_reason_error_string e)
             (ERR_lib_error_string e) 
             (ERR_func_error_string e) 
             e))))
    (format "libcrypto error: ~a ~a"
      (or errstr "?")
      (or info ""))))

(define (raise-crypto-error where (info #f))
  (error where (format-crypto-error (ERR_get_error) info)))

(define (mismatch-error where fmt . args)
  (raise 
    (make-exn:fail:contract 
     (string-append (symbol->string where) ": " (apply format fmt args))
     (current-continuation-marks))))

(define (check-error where r)
  (unless (> r 0)
    (raise-crypto-error where)))

(define (pointer/error where r)
  (or r (raise-crypto-error where "(nil)")))

(define (int/error where r)
  (if (> r 0) r (raise-crypto-error where)))

(define (int/error* where r)
  (if (< r 0) (raise-crypto-error where) r))

(define (bool/error where r)
  (case r
    ((1) #t)
    ((0) #f)
    (else (raise-crypto-error where))))

(define-rules check-input-range ()
  ((_ where bs maxlen)
   (unless (<= (bytes-length bs) maxlen)
     (mismatch-error 'where "bad input range")))
  ((_ where bs start end)
   (unless (and (<= 0 start) (< start end) (<= end (bytes-length bs)))
     (mismatch-error 'where "bad input range")))
  ((_ where bs start end maxlen)
   (unless (and (<= 0 start) (< start end) (<= end (bytes-length bs))
                (<= (- end start) maxlen))
     (mismatch-error 'where "bad input range"))))

(define-rules check-output-range ()
  ((_ where bs minlen)
   (begin
     (when (or (not (bytes? bs)) (immutable? bs))
       (mismatch-error 'where "expects mutable bytes"))
     (unless (>= (bytes-length bs) minlen)
       (mismatch-error 'where "bad output range"))))
  ((_ where bs start end)
   (begin
     (when (or (not (bytes? bs)) (immutable? bs))
       (mismatch-error 'where "expects mutable bytes"))
     (unless (and (<= 0 start) (< start end) (<= end (bytes-length bs)))
       (mismatch-error 'where "bad output range"))))
  ((_ where bs start end minlen)
   (begin
     (when (or (not (bytes? bs)) (immutable? bs))
       (mismatch-error 'where "expects mutable bytes"))
     (unless (and (<= 0 start) (< start end) (<= end (bytes-length bs))
                  (>= (- end start) minlen))
       (mismatch-error 'where "bad output range")))))
