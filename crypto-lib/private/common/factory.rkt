;; Copyright 2013-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         racket/list
         racket/contract/base
         racket/string
         brandx
         "catalog.rkt"
         "interfaces.rkt"
         "digest.rkt"
         "kdf.rkt")
(provide (struct-out factory-base)
         (struct-out common-factory)
         (interface-out inner-fetch$)
         (struct-out inner-fetch-base)
         make-factory)

;; ============================================================
;; Factory

(struct factory-base
  (name         ;; Symbol
   version      ;; ??
   ok?          ;; Boolean
   load-error   ;; (U String #f)
   )
  #:properties
  (method-properties
   #:export ([factory$ #:prefix %]
             [simple-write$ #:prefix %])
   (define-struct-abbrevs factory-base)
   (define (%to-write-string self)
     ($factory-display-name self))
   (define (%to-write-prefixes self)
     '(factory))

   ;; ----

   (define (%factory-name self) (.name self))
   (define (%factory-version self) (.version self))
   (define (%factory-display-name self)
     (format "~a:~a"
             (or (.name self) "?")
             (let ([version (and (.ok? self) (.version self))])
               (cond [(not version) "failed"]
                     [(null? version) "?"]
                     [else (string-join (map number->string version) ".")]))))

   (define (%factory-info self key)
     (case key
       [(version) (and (.ok? self) (.version self))]
       [(all-digests) (filter (lambda (s) ($fetch-digest self s)) (list-known-digests))]
       [(all-ciphers) (filter (lambda (x) ($fetch-cipher self x)) (list-known-ciphers))]
       [(all-kdfs)    (filter (lambda (k) ($fetch-kdf self k))    (list-known-kdfs))]
       [(all-pks)     (filter (lambda (x) ($fetch-pk self x))     (list-known-pks))]
       [(all-curves)  (append ($factory-info self 'all-ec-curves)
                              ($factory-info self 'all-eddsa-curves)
                              ($factory-info self 'all-ecx-curves))]
       [(all-ec-curves)    '()]
       [(all-eddsa-curves) '()]
       [(all-ecx-curves)   '()]
       [else #f]))

   (define (%factory-print self)
     (printf "Library info:\n")
     (print-lib-info self)
     (print-avail self)
     (void))

   (define (print-lib-info self)
     (printf " name: ~s\n" (.name self))
     (printf " version: ~s\n" (.version self))
     (let ([load-error (.load-error self)])
       (when load-error (printf " load error: ~s\n" load-error)))
     (for ([extra (in-list (or ($factory-info self 'extra-lib-info) null))])
       (match-define (list key val) extra)
       (printf " ~a: ~s\n" key val)))

   (define (print-avail self)
     (define (pad-to v len)
       (let ([vs (format "~a" v)])
         (string-append vs (make-string (- len (string-length vs)) #\space))))
     (define all-digests ($factory-info self 'all-digests))
     (define all-ciphers ($factory-info self 'all-ciphers))
     ;; == Digests ==
     (when (pair? all-digests)
       (printf "Available digests:\n")
       (for ([di (in-list all-digests)])
         (printf " ~v\n" di)))
     ;; == Ciphers ==
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
               [else (printf " ~v\n" (car group))])))
     ;; == PK ==
     (let ([all-pks ($factory-info self 'all-pks)])
       (when (pair? all-pks)
         (printf "Available PKs:\n")
         (for ([pk (in-list all-pks)])
           (printf " ~v\n" pk))))
     ;; == EC named curves ==
     (let ([all-curves ($factory-info self 'all-ec-curves)])
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
     (let ([all-curves ($factory-info self 'all-eddsa-curves)])
       (when (pair? all-curves)
         (printf "Available 'eddsa named curves:\n")
         (for ([curve (in-list all-curves)])
           (printf " ~v\n" curve))))
     ;; == EC/X named curves ==
     (let ([all-curves ($factory-info self 'all-ecx-curves)])
       (when (pair? all-curves)
         (printf "Available 'ecx named curves:\n")
         (for ([curve (in-list all-curves)])
           (printf " ~v\n" curve))))
     ;; == KDFs ==
     (let ([all-kdfs ($factory-info self 'all-kdfs)])
       (when (pair? all-kdfs)
         (printf "Available KDFs:\n")
         (for ([kdf (in-list all-kdfs)] #:when (symbol? kdf))
           (printf " ~v\n" kdf))
         (define (show-complex label dspec->kdfspec)
           (cond [(null? all-digests) (void)]
                 [(for/and ([dspec (in-list all-digests)]
                            #:when (basic-digest-spec? dspec))
                    (member (dspec->kdfspec dspec) all-kdfs))
                  (printf " ~a  for all available basic digests\n" label)]
                 [else
                  (for ([dspec (in-list all-digests)])
                    (define kdfspec (dspec->kdfspec dspec))
                    (when (member kdfspec all-kdfs)
                      (printf " ~v\n" (dspec->kdfspec dspec))))]))
         (show-complex "`(pbkdf2 hmac ,digest)                   "
                       (lambda (ds) `(pbkdf2 hmac ,ds)))
         (show-complex "`(hkdf ,digest)                          "
                       (lambda (ds) `(hkdf ,ds)))
         (show-complex "`(concat ,digest)                        "
                       (lambda (ds) `(concat ,ds)))
         (show-complex "`(concat hmac ,digest)                   "
                       (lambda (ds) `(concat hmac ,ds)))
         (show-complex "`(ans-x9.63 ,digest)                     "
                       (lambda (ds) `(ans-x9.63 ,ds)))
         (show-complex "`(sp800-108-counter hmac ,digest)        "
                       (lambda (ds) `(sp800-108-counter hmac ,ds)))
         (show-complex "`(sp800-108-feedback hmac ,digest)       "
                       (lambda (ds) `(sp800-108-counter hmac ,ds)))
         (show-complex "`(sp800-108-double-pipeline hmac ,digest)"
                       (lambda (ds) `(sp800-108-counter hmac ,ds)))
         (void)))
     (void))
   ))

(struct common-factory factory-base
  (inner        ;; InnerFetch
   table        ;; (Hash *Spec => *Impl)
   get-info     ;; (Symbol -> (U Any #f))
   ctx          ;; impl-specific
   )
  #:properties
  (method-properties
   #:export ([factory$ #:prefix %])
   #:import ([factory$ #:super])
   (define-struct-abbrevs common-factory)

   (define (%factory-info self key)
     (or ((.get-info self) key)
         (super-factory-info self key)))

   (define (%factory-inner-ctx self)
     (.ctx self))

   (define (%fetch-digest self dspec)
     (fetch self dspec digest-spec->info $fi-digest))

   (define (%fetch-cipher self cspec)
     (fetch self cspec cipher-spec->info $fi-cipher))

   (define (%fetch-kdf self kdfspec)
     (fetch self kdfspec kdf-spec->info $fi-kdf))

   (define (%fetch-pk self pkspec)
     (fetch self pkspec pk-spec->info $fi-pk))

   (define (fetch self spec spec->info inner-fetch)
     (hash-ref! (.table self) spec
                (lambda ()
                  (inner-fetch (.inner self) self (spec->info spec)))))
   ))

;; ============================================================

(define-interface inner-fetch$
  ([fi-digest
    (-> inner-fetch$? factory? digest-info?
        (or/c digest-impl? #f))]
   [fi-cipher
    (-> inner-fetch$? factory? cipher-info?
        (or/c cipher-impl? #f))]
   [fi-kdf
    (-> inner-fetch$? factory? kdf-info?
        (or/c kdf-impl? #f))]
   [fi-pk
    (-> inner-fetch$? factory? pk-info?
        (or/c pk-impl? #f))])
  #:generics-prefix $)

;; ----------------------------------------

(struct inner-fetch-base ()
  #:properties
  (method-properties
   #:export ([inner-fetch$ #:prefix %])

   (define (%fi-digest self factory info)
     (match ($get-spec info)
       [(list 'hmac dspec)
        (define di ($fetch-digest factory dspec))
        (define inner (and di (rkt-hmac-inner-impl di)))
        (make-digest info factory inner)]
       [_ #f]))

   (define (%fi-cipher self factory info)
     #f)

   (define (%fi-pk self factory info)
     #f)

   (define (%fi-kdf self factory info)
     (define (make-kdf inner)
       (common-kdf-impl info factory inner))
     (match ($get-spec info)
       [(list 'hkdf dspec)
        (define di ($fetch-digest factory `(hmac ,dspec)))
        (and di (make-kdf (hkdf-inner-impl di)))]
       [(list 'concat dspec)
        (define di ($fetch-digest factory dspec))
        (and di (make-kdf (concat-kdf-inner-impl di #f)))]
       [(list 'concat 'hmac (? symbol? dspec))
        (define di ($fetch-digest factory `(hmac ,dspec)))
        (and di (make-kdf (concat-kdf-inner-impl di #t)))]
       [(list 'ans-x9.63 dspec)
        (define di ($fetch-digest factory dspec))
        (and di (make-kdf (ans-x9.63-kdf-inner-impl di)))]
       [(list 'sp800-108-counter 'hmac dspec)
        (define di ($fetch-digest factory dspec))
        (and di (make-kdf (sp800-108-counter-hmac-kdf-inner-impl di)))]
       [(list 'sp800-108-feedback 'hmac dspec)
        (define di ($fetch-digest factory dspec))
        (and di (make-kdf (sp800-108-feedback-hmac-kdf-inner-impl di)))]
       [(list 'sp800-108-double-pipeline 'hmac dspec)
        (define di ($fetch-digest factory dspec))
        (and di (make-kdf (sp800-108-double-pipeline-hmac-kdf-inner-impl di)))]
       [_ #f]))
   ))

(struct common-inner-fetch inner-fetch-base
  (fetch-digest
   fetch-cipher
   fetch-kdf
   fetch-pk
   )
  #:properties
  (method-properties
   #:export ([inner-fetch$ #:prefix %])
   #:import ([inner-fetch$ #:super])
   (define-struct-abbrevs common-inner-fetch)

   (define (%fi-digest self factory info)
     (or ((.fetch-digest self) factory info)
         (super-fi-digest self factory info)))

   (define (%fi-cipher self factory info)
     (or ((.fetch-cipher self) factory info)
         (super-fi-cipher self factory info)))

   (define (%fi-kdf self factory info)
     (or ((.fetch-kdf self) factory info)
         (super-fi-kdf self factory info)))

   (define (%fi-pk self factory info)
     (or ((.fetch-pk self) factory info)
         (super-fi-pk self factory info)))
   ))

;; ============================================================

(define (make-factory #:name name
                      #:version version
                      #:ok? [ok? #f]
                      #:load-error [load-error #f]
                      #:inner-ctx [ic #f]
                      #:get-info [get-info #f]
                      #:get-digest [get-digest #f]
                      #:get-cipher [get-cipher #f]
                      #:get-kdf [get-kdf #f]
                      #:get-pk [get-pk #f])
  (define (fetch-none factory info) #f)
  (define (get-none key) #f)
  (define table (make-hash))
  (define inner
    (common-inner-fetch (or get-digest fetch-none)
                        (or get-cipher fetch-none)
                        (or get-kdf fetch-none)
                        (or get-pk fetch-none)))
  (common-factory name version ok? load-error
                  inner table (or get-info get-none) ic))
