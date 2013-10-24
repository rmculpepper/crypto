#lang scribble/doc
@(require scribble/manual
          scribble/basic
          (for-label racket/base
                     racket/contract
                     crypto))

@title{Crypto: Cryptographic Operations}
@author[@author+email["Ryan Culpepper" "ryanc@racket-lang.org"]]

@defmodule[crypto]

This library provides a high-level interface for cryptographic
operations.  To use this library you will need OpenSSL (0.9.8 or
later) installed on your system.

@bold{Development} Development of this library is hosted by
@hyperlink["http://github.com"]{GitHub} at the following project page:

@centered{@url{https://github.com/rmculpepper/crypto}}

@bold{Copying} This program is free software: you can redistribute
it and/or modify it under the terms of the
@hyperlink["http://www.gnu.org/licenses/lgpl.html"]{GNU Lesser General
Public License} as published by the Free Software Foundation, either
version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License and GNU Lesser General Public License for more
details.

@include-section["digest.scrbl"]
@include-section["cipher.scrbl"]
@include-section["pkey.scrbl"]
@include-section["dh.scrbl"]
@include-section["util.scrbl"]
@include-section["examples.scrbl"]
