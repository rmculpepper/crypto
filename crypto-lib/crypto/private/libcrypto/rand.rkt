;; Copyright 2012-2013 Ryan Culpepper
;; Copyright 2007-2009 Dimitris Vyzovitis <vyzo at media.mit.edu>
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
         ffi/unsafe
         ffi/file
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide libcrypto-random-impl%)

(define libcrypto-random-impl%
  (class* impl-base% (random-impl<%>)
    (super-new)
    (define/public (random-bytes! who buf start end _level)
      (check-output-range who buf start end)
      (void (RAND_bytes (ptr-add buf start) (- end start))))

    (define/public (ok?)
      (= (RAND_status) 1))

    (define/public (can-add-entropy?) #t)

    (define/public (add-entropy who buf entropy-in-bytes)
      (void (RAND_add buf (bytes-length buf) entropy-in-bytes)))

    (define/public (load-file file max-bytes)
      (let ([max-bytes (if (= max-bytes +inf.0) -1 max-bytes)])
        (security-guard-check-file 'rand-load-file file '(read))
        (void (RAND_load_file file max-bytes))))

    (define/public (rand-write-file file)
      (security-guard-check-file 'rand-write-file file '(write))
      (void (RAND_write_file file)))
    ))
