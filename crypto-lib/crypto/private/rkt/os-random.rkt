;; Copyright 2013-2014 Ryan Culpepper
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
(require racket/contract/base
         (rename-in ffi/unsafe [-> -->])
         ffi/unsafe/define
         "../common/error.rkt")
(provide
 (contract-out
  [os-random-bytes
   (-> exact-nonnegative-integer? bytes?)]))

;; Use os-random-bytes to seed CSPRNGs.
;; - on unix-like systems, use /dev/urandom
;;   FIXME: blacklist unixes with bad /dev/urandom (???)
;; - on Windows, use RtlGenRandom syscall

(define os-random-bytes
  (case (system-type)
    [(windows)
     ;; Reference:
     ;; - http://msdn.microsoft.com/en-us/library/windows/desktop/aa387694%28v=vs.85%29.aspx
     (define-ffi-definer define-advapi (ffi-lib "advapi.dll" #:fail (lambda () #f))
       #:default-make-fail make-not-available)
     (define-advapi RtlGenRandom
       (_fun _pointer _ulong --> _bool)
       #:c-id SystemFunction036)
     (define (windows-random-bytes n)
       (define buf (make-bytes n 0))
       (or (RtlGenRandom buf n)
           (crypto-error "error in RtlGenRandom"))
       buf)
     windows-random-bytes]
    [(unix macosx)
     (define (unix-random-bytes n)
       (call-with-input-file "/dev/urandom"
         (lambda (in)
           (read-bytes n in))))
     unix-random-bytes]
    [else
     (lambda (n)
       (crypto-error "unknown OS type\n  OS: ~s" (system-type)))]))
