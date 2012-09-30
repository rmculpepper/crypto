;; mzcrypto: libcrypto bindings for PLT-scheme
;; engine support
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

(require "macros.ss" 
         "libcrypto.ss")
(provide (all-defined-out))

(define/ffi (ENGINE_load_builtin_engines))
(define/ffi (ENGINE_register_all_complete))
(define/ffi (ENGINE_cleanup))

(define (engine-load-builtin)
  (ENGINE_load_builtin_engines)
  (ENGINE_register_all_complete))

(define (engine-cleanup)
  (ENGINE_cleanup))

(define-symbols engine.symbols 
  engine-load-builtin
  engine-cleanup)
(define-provider provide-engine engine.symbols)



