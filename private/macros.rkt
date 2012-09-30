;; mzcrypto: libcrypto bindings for PLT-scheme
;; support macros
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

(require scheme/base 
         (for-syntax scheme/base "stx-util.rkt")
         (for-template scheme/base))

(provide (all-defined-out)
         (rename-out (call-with-values call/values)
                     (add1 1+)
                     (sub1 1-)))

(define-syntax (define-rule stx)
  (syntax-case stx ()
    ((_ (id . args) body)
     (syntax/loc stx
       (define-syntax id
         (lambda (stx)
           (syntax-case stx ()
             ((_ . args) (syntax/loc stx body)))))))))

(define-syntax (define-rules stx)
  (syntax-case stx ()
    ((_ id (lit ...) (pat res) ...)
     (syntax/loc stx
       (define-syntax id
         (lambda (stx)
           (syntax-case stx (lit ...)
             (pat (syntax/loc stx res)) ...)))))))

(define-syntax (@string stx)
  (syntax-case stx ()
    ((_ tgt) (datum->syntax stx (/string (syntax-e #'tgt))))))

(define-rule (push! var obj)
  (set! var (cons obj var)))

(define-rules alet* ()
  ((_ () body ...) (begin body ...))
  ((self ((id expr) . rest) body ...)
   (let ((id expr))
     (if id (self rest body ...) #f))))

(define-rule (define* id . body)
  (define id (case-lambda . body)))

(define-rule (lambda/name id hd . body)
  (let ((id (lambda hd . body))) id))

(define-rules define-symbols ()
  ((_ id)
   (define-syntax id (box null)))
  ((self id sym ...)
   (begin (self id) (put-symbols! id sym ...))))

(define-syntax (put-symbols! stx)
  (syntax-case stx ()
    ((_ tgt sym ...)
     (let ((syms (syntax-local-value #'tgt))
           (cert (syntax-local-certifier)))
       (set-box! syms
         (foldl (lambda (x r)
                  (syntax-case x ()
                    ((id id*) (cons (cons (cert #'id) (cert #'id*)) r))
                    (id (cons (cert #'id) r))))
           (unbox syms) (syntax->list #'(sym ...))))
       #'(begin)))))

(define-syntax (define-provider stx)
  (syntax-case stx ()
    ((_ id tgt)
     (with-syntax (((spec ...)
                    (map (lambda (x)
                           (syntax-case x ()
                             ((id . id*) #'(rename-out (id id*)))
                             (id #'id)))
                      (unbox (syntax-local-value #'tgt)))))
     (syntax/loc stx
       (define-rule (id)
         (provide spec ...)))))))

