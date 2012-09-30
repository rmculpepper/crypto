;; mzcrypto: libcrypto bindings for PLT-scheme
;; syntax utilities
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
#lang scheme/base

(provide (all-defined-out))

(define (/identifier stx . args)
  (datum->syntax stx (apply make-symbol args)))

(define (/string x)
  (cond
   ((string? x) x)
   ((symbol? x) (symbol->string x))
   ((number? x) (number->string x))
   ((syntax? x) (/string (syntax-e x)))
   (else (error '/string))))

(define (/symbol x)
  (cond
   ((symbol? x) x)
   ((string? x) (string->symbol x))
   ((syntax? x) (/symbol (syntax-e x)))
   (else (error '/symbol))))

(define (make-symbol . args)
  (string->symbol (apply string-append (map /string args))))
