;; Copyright 2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require "main.rkt"
         "libcrypto.rkt"
         "gcrypt.rkt"
         "nettle.rkt"
         "argon2.rkt"
         "b2.rkt"
         "decaf.rkt"
         "sodium.rkt")
(provide all-factories
         use-all-factories!

         libcrypto-factory
         gcrypt-factory
         nettle-factory
         argon2-factory
         b2-factory
         decaf-factory
         sodium-factory)

(define all-factories
  (list nettle-factory
        libcrypto-factory
        gcrypt-factory
        b2-factory
        argon2-factory
        sodium-factory
        decaf-factory))

(define (use-all-factories!)
  (crypto-factories all-factories))
