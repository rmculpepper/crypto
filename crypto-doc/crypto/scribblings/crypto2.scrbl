#lang scribble/doc
@(require scribble/manual
          scribble/basic
          planet/scribble
          (for-label racket/base
                     racket/contract
                     (this-package-in main)))

@title{Crypto2}

@defmodule/this-package[main]

mzcrypto is a cryptographic library for mzscheme.

The library provides a high level interface for accessing primitives
from libcrypto.
To use this library you will need OpenSSL (0.9.8 or later) installed on 
your system.

(C) Copyright 2007-2009 Dimitris Vyzovitis <vyzo at media.mit.edu>
 
This library is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.
 
You should have received a copy of the GNU Lesser General Public License
 along with this library.  If not, see 
@link["http://www.gnu.org/licenses/"]{<http://www.gnu.org/licenses/>}.

@include-section["digest.scrbl"]
@include-section["cipher.scrbl"]
@include-section["pkey.scrbl"]
@include-section["dh.scrbl"]
@include-section["util.scrbl"]
@include-section["examples.scrbl"]
