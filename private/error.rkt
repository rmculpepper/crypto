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
         ffi/unsafe/atomic
         "macros.rkt"
         "libcrypto.rkt")
(provide (all-defined-out))

;; FIXME: race condition in retrieving error number
;; A better approach would be to make wrapper functions that
;; did the main FFI call in atomic mode.

(define-crypto ERR_get_error
  (_fun -> _ulong))
(define-crypto ERR_peek_last_error
  (_fun -> _ulong))
(define-crypto ERR_lib_error_string
  (_fun _ulong -> _string))
(define-crypto ERR_func_error_string
  (_fun _ulong -> _string))
(define-crypto ERR_reason_error_string
  (_fun _ulong -> _string))

;; ----

(define (((err-wrap who ok? [convert values]) proc) . args)
  (call-as-atomic
   (lambda ()
     (let ([result (apply proc args)])
       (if (ok? result)
           (convert result)
           (raise-crypto-error who))))))

(define (err-wrap/check who)
  (err-wrap who positive? void))

(define (err-wrap/pointer who)
  (err-wrap who values))

#|
** check-error -> (err-wrap _ positive? void)
(define (check-error where r)
  (unless (> r 0)
    (raise-crypto-error where)))
** pointer/error -> (err-wrap _ values)
(define (pointer/error where r)
  (or r (raise-crypto-error where "(nil)")))
** int/error -> (err-wrap _ positive?)
(define (int/error where r)
  (if (> r 0) r (raise-crypto-error where)))
** int/error* -> (err-wrap _ nonnegative-exact-integer?)
(define (int/error* where r)
  (if (< r 0) (raise-crypto-error where) r))
** bool/error -> (err-wrap _ '(0 1) integer->boolean)
(define (bool/error where r)
  (case r
    ((1) #t)
    ((0) #f)
    (else (raise-crypto-error where))))
|#

(define (raise-crypto-error where (info #f))
  (let* ([e (ERR_get_error)]
         [le (ERR_lib_error_string e)]
         [fe (and le (ERR_func_error_string e))]
         [re (and fe (ERR_reason_error_string e))])
    (error where "~a [~a:~a:~a]~a~a"
           (or (ERR_reason_error_string e) "?")
           (or (ERR_lib_error_string e) "?")
           (or (ERR_func_error_string e) "?")
           e
           (if info " " "")
           (or info ""))))

;; ----

(define (mismatch-error where fmt . args)
  (raise 
    (make-exn:fail:contract 
     (string-append (symbol->string where) ": " (apply format fmt args))
     (current-continuation-marks))))

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
