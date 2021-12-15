;; Test d2i functions for memory corruption

#lang racket/base
(require crypto
         crypto/libcrypto)

(crypto-factories (list libcrypto-factory))

(module+ test
  (printf "Skipping long-running test.\n"))

(module+ main

  ;; ----------------------------------------
  ;; Version 1

  (define ITERS1 #e1e5)

  (define k (generate-private-key 'ec '((curve secp256r1))))

  (for ([i (in-range ITERS1)])
    (datum->pk-key (pk-key->datum k 'rkt-public) 'rkt-public))

  ;; ----------------------------------------
  ;; Version 2

  (define ITERS2 #e1e5)

  ;; The for/list, for/sum and maps seem to be necessary to get the GC
  ;; going at the right moments.

  (void
   (map sync
        (for/list ([t 2])
          (thread
           (lambda ()
             (for ([i (in-range ITERS2)])
               (when #f
                 (when (zero? (modulo i #e5e3))
                   (printf "thread #~s iteration #~s\n" t i)))
               (define xs (for/list ([i 10]) i))
               (define k (generate-private-key 'ec '((curve secp256r1))))
               (define p (map values (pk-key->datum k 'rkt-public)))
               (define q (map values (pk-key->datum k 'rkt-private)))
               (unless (pk-verify (datum->pk-key p 'rkt-public)
                                  #"asdfasdf"
                                  (pk-sign (datum->pk-key q 'rkt-private)
                                           #"asdfasdf"))
                 (error 'bad))
               (for/sum ([x xs]) x)))))))

  ;; ----------------------------------------
  (module config info
    (define timout 240)))
