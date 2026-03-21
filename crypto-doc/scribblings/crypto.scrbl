#lang scribble/manual
@(require scribble/basic
          (for-label racket/base
                     racket/contract
                     crypto))

@title[#:version "2.0"]{Crypto: Cryptographic Operations}
@author[@author+email["Ryan Culpepper" "ryanc@racket-lang.org"]]

@defmodule[crypto]

This library provides an interface for cryptographic operations,
including message digests, symmetric-key encryption, and public-key
signatures, encryption, and key agreement.

@bold{Development} Development of this library is hosted by
@hyperlink["http://github.com"]{GitHub} at the following project page:

@centered{@url{https://github.com/rmculpepper/crypto}}

@local-table-of-contents[]

@include-section["intro.scrbl"]
@include-section["factory.scrbl"]
@include-section["digest.scrbl"]
@include-section["cipher.scrbl"]
@include-section["pkey.scrbl"]
@include-section["kdf.scrbl"]
@include-section["util.scrbl"]
@include-section["misc.scrbl"]
