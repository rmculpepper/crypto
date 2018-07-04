;; Copyright 2013-2018 Ryan Culpepper
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
         racket/list
         "catalog.rkt"
         "interfaces.rkt"
         "cipher.rkt")
(provide factory-base%)

;; ============================================================
;; Factory

(define factory-base%
  (class* object% (factory<%>)
    (init-field [ok? #t])
    (super-new)

    (define/public (get-name) #f)
    (define/public (get-version) (and ok? '()))

    (define/public (info key)
      (case key
        [(version) (and ok? (get-version))]
        [(all-digests) (filter (lambda (s) (get-digest s)) (list-known-digests))]
        [(all-ciphers) (filter (lambda (x) (get-cipher x)) (list-known-ciphers))]
        [(all-pks)     (filter (lambda (x) (get-pk x))     (list-known-pks))]
        [(all-ec-curves)    '()]
        [(all-eddsa-curves) '()]
        [(all-ecx-curves)   '()]
        [(all-kdfs)    (filter (lambda (k) (get-kdf k))    (list-known-kdfs))]
        [else #f]))

    (define/public (print-info)
      (void))

    (define/public (print-avail)
      (define (pad-to v len)
        (let ([vs (format "~a" v)])
          (string-append vs (make-string (- len (string-length vs)) #\space))))
      ;; == Digests ==
      (let ([all-digests (info 'all-digests)])
        (when (pair? all-digests)
          (printf "Available digests:\n")
          (for ([di (in-list (info 'all-digests))])  (printf " ~v\n" di))))
      ;; == Ciphers ==
      (let ([all-ciphers (info 'all-ciphers)])
        (when (pair? all-ciphers)
          (printf "Available ciphers:\n")
          (define cipher-groups (group-by car all-ciphers))
          (define cipher-max-len
            (apply max 0 (for/list ([cg (in-list cipher-groups)] #:when (> (length cg) 1))
                           (string-length (symbol->string (caar cg))))))
          (for ([group (in-list cipher-groups)])
            (cond [(> (length group) 1)
                   (printf " `(~a ,mode)  for mode in ~a\n"
                           (pad-to (car (car group)) cipher-max-len)
                           (map cadr group))]
                  [else (printf " ~v\n" (car group))]))))
      ;; == PK ==
      (let ([all-pks (info 'all-pks)])
        (when (pair? all-pks)
          (printf "Available PKs:\n")
          (for ([pk (in-list all-pks)]) (printf " ~v\n" pk))))
      ;; == EC named curves ==
      (let ([all-curves (info 'all-ec-curves)])
        (define all-curve-vs (for/list ([c (in-list all-curves)]) (format "~v" c)))
        (when (pair? all-curves)
          (printf "Available 'ec named curves:\n")
          (define curve-max-len (apply max 0 (map string-length all-curve-vs)))
          (for ([curve (in-list all-curves)] [curve-v (in-list all-curve-vs)])
            (define aliases (remove curve (curve-name->aliases curve)))
            (cond [(null? aliases)
                   (printf " ~a\n" curve-v)]
                  [else
                   (printf " ~a  with aliases ~s\n"
                           (pad-to curve-v curve-max-len)
                           aliases)]))))
      ;; == EdDSA named curves ==
      (let ([all-curves (info 'all-eddsa-curves)])
        (when (pair? all-curves)
          (printf "Available 'eddsa named curves:\n")
          (for ([curve (in-list all-curves)])
            (printf " ~v\n" curve))))
      ;; == EC/X named curves ==
      (let ([all-curves (info 'all-ecx-curves)])
        (when (pair? all-curves)
          (printf "Available 'ecx named curves:\n")
          (for ([curve (in-list all-curves)])
            (printf " ~v\n" curve))))
      ;; == KDFs ==
      (let ([all-kdfs (info 'all-kdfs)])
        (when (pair? all-kdfs)
          (printf "Available KDFs:\n")
          (for ([kdf (in-list all-kdfs)] #:when (symbol? kdf))
            (printf " ~v\n" kdf))
          (let ([all-digests (info 'all-digests)])
            (cond [(null? all-digests) (void)]
                  [(for/and ([di (in-list all-digests)]) (get-kdf `(pbkdf2 hmac ,di)))
                   (printf " `(pbkdf2 hmac ,digest)  for all available digests\n")]
                  [else
                   (for ([di (in-list all-digests)] #:when (get-kdf `(pbkdf2 hmac ,di)))
                     (printf " ~v\n" `(pbkdf2 hmac ,di)))]))))
      (void))

    ;; table : Hash[*Spec => *Impl]
    ;; Note: assumes different *Spec types have disjoint values!
    ;; Only cache successful lookups to keep table size bounded.
    (field [table (make-hash)])

    (define-syntax-rule (get/table spec spec->key get-impl)
      ;; Note: spec should be variable reference
      (cond [(not ok?) #f]
            [(hash-ref table spec #f) => values]
            [(spec->key spec)
             => (lambda (key)
                  (cond [(get-impl key)
                         => (lambda (impl)
                              (hash-set! table (send impl get-spec) impl)
                              impl)]
                        [else #f]))]
            [else #f]))

    (define/public (get-digest spec)
      (get/table spec digest-spec->info -get-digest))
    (define/public (get-cipher spec)
      (get/table spec cipher-spec->info -get-cipher0))
    (define/public (get-pk spec)
      (get/table spec values -get-pk))
    (define/public (get-kdf spec)
      (get/table spec values -get-kdf))
    (define/public (get-pk-reader)
      (get/table '*pk-reader* values (lambda (k) (-get-pk-reader))))

    (define/public (-get-cipher0 info)
      (define ci (-get-cipher info))
      (cond [(cipher-impl? ci) ci]
            [(and (list? ci) (pair? ci) (andmap cdr ci))
             (new multikeylen-cipher-impl% (info info) (factory this) (impls ci))]
            [else #f]))

    ;; -get-digest : digest-info -> (U #f digest-impl)
    (define/public (-get-digest info) #f)

    ;; -get-cipher : cipher-info -> (U #f cipher-impl (listof (cons Nat cipher-impl)))
    (define/public (-get-cipher info) #f)

    ;; -get-pk : pk-spec -> (U pk-impl #f)
    (define/public (-get-pk spec) #f)

    ;; -get-pk-reader : -> (U pk-read-key #f)
    (define/public (-get-pk-reader) #f)

    ;; -get-kdf : -> (U kdf-impl #f)
    (define/public (-get-kdf spec) #f)
    ))
