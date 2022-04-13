#lang racket/base
(require racket/match
         racket/list
         scramble/result)
(provide (all-defined-out))

;; ------------------------------------------------------------
;; Results

;; filter-results : (Listof (Result X Y))
;;                  #:good ((Listof X) -> X*)
;;                  #:bad ((Listof Y) -> Y*)
;;               -> (Result (Listof X*) (Listof Y*))
(define (filter-results rs
                        #:good [good-f values]
                        #:bad [bad-f values]
                        #:empty-ok? [empty-ok? #t])
  (define-values (goodvs badvs) (partition-results rs))
  (cond [(pair? goodvs) (ok (good-f goodvs))]
        [empty-ok? (ok null)]
        [else (bad (bad-f badvs))]))

;; append*-results : (Listof (Result X (Listof Y))) -> (Result X (Listof Y))
(define (append*-results rs)
  (define-values (goodvs badvs) (partition-results rs))
  (if (pair? badvs) (bad (append* badvs)) (ok (andmap values goodvs))))

;; append-results : (Result X (Listof Y)) ... -> (Result X (Listof Y))
(define (append-results . rs) (append*-results rs))

;; bad-map : (Y -> Z) (Result X (Listof Y)) -> (Result X (Listof Z))
(define (bad-map f r)
  (match r
    [(? ok?) r]
    [(bad vs) (bad (map f vs))]))
