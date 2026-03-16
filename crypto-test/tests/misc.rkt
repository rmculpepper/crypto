;; Copyright 2022-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require checkers
         crypto/private/common/common)

(test #:name "misc"
  (check (version->list #f) #:is #f)
  (check (version->list "123") #:is '(123))
  (check (version->list "1.2.3.4.5.6") #:is '(1 2 3 4 5 6))
  (check (version->list "1.10.1-unknown") #:is '(1 10 1)))
