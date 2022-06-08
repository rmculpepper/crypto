#lang racket/base
(require rackunit
         crypto/private/common/common)

(check-equal? (version->list #f)
              #f)

(check-equal? (version->list "123")
              '(123))

(check-equal? (version->list "1.2.3.4.5.6")
              '(1 2 3 4 5 6))

(check-equal? (version->list "1.10.1-unknown")
              '(1 10 1))
