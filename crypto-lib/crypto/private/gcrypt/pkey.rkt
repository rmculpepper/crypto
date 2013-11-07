;; Copyright 2013 Ryan Culpepper
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
(require ffi/unsafe
         "ffi.rkt")
(provide (all-defined-out))

;; Supported algorithms:
;;  RSA, DSA, ElGamal
;;  elliptic curve versions of DSA ???

(define (rsa-keygen-params nbits)
  (gcry_sexp_build "(genkey (rsa (nbits %s)))" (string->bytes/utf-8 (number->string nbits))))

(define (keygen-rsa)
  (define params (rsa-keygen-params 2048))
  (gcry_pk_genkey params))

(define (key->bytes k [fmt 'gcrypt-sexp])
  (case fmt
    [(gcrypt-sexp)
     (gcry_sexp->bytes k)]
    [(pkcs1-der)
     (error 'unimplemented)]))

(define (bytes->key k-buf [fmt 'gcrypt-sexp])
  (case fmt
    [(gcrypt-sexp)
     (gcry_sexp_new k-buf)]
    [(pkcs1-der)
     (error 'unimplemented)]))

;; RSA
;;   encrypt/decrypt : public (or private) => private
;;   sign/verify     : private => public (or private)
;; DSA
;;   encrypt/decrypt : no
;;   sign/verify     : private => public (or private)
;; ElGamal
;;   encrypt/decrypt : public (or private) => private
;;   sign/verify     : private => public (or private)

;; <padding> = raw | pkcs1 | oaep | pss
;; Other flags include no-blinding to disable blinding (enabled by default, RSA only)

;; Encrypt:
;; (data (flags <padding>) (value <data>))
;; ->
;; (enc-val (rsa (a <data>)))             ;; RSA
;; (enc-val (elg (a <data>) (b <data>)))  ;; ElGamal
(define (rsa-encrypt key data padding)
  (define data-sexp
    (gcry_sexp_build "(data (flags %s) (value %b))"
                     padding
                     (cast (bytes-length data) _uintptr _pointer) ;; bleh, hack
                     data))
  (define enc-sexp
    (gcry_pk_encrypt data-sexp key))
  (define enc-part
    (gcry_sexp_find_token enc-sexp "rsa"))
  (define enc-a-part
    (gcry_sexp_find_token enc-part "a"))
  (define enc-mpi
    (gcry_sexp_nth_mpi enc-a-part 1))
  (define enc-mpi-bits
    (gcry_mpi_get_nbits enc-mpi))
  (define mpi-buf
    (make-bytes (add1 (quotient enc-mpi-bits 8))))
  (define nwrote
    (gcry_mpi_print GCRYMPI_FMT_USG enc-mpi mpi-buf))
  (define enc-data
    (subbytes mpi-buf 0 nwrote))
  (gcry_mpi_release enc-mpi)
  (gcry_sexp_release enc-a-part)
  (gcry_sexp_release enc-part)
  (gcry_sexp_release enc-sexp)
  (gcry_sexp_release data-sexp)
  enc-data)

;; Decrypt
;; (enc-val (flags <padding>) (rsa (a <data>)))
;; (enc-val (flags <padding>) (elg (a <data>) (b <data>)))
;; =>
;; (value <data>)
(define (rsa-decrypt key data padding)
  (define enc-sexp
    (gcry_sexp_build "(enc-val (flags %s) (rsa (a %b)))"
                     padding
                     (cast (bytes-length data) _uintptr _pointer)
                     data))
  (define dec-sexp
    (gcry_pk_decrypt enc-sexp key))
  (define dec-data
    (gcry_sexp_nth_data dec-sexp 1))
  (gcry_sexp_release enc-sexp)
  (gcry_sexp_release dec-sexp)
  dec-data)

;; Sign
;; (data (flags <padding>) (hash <hash-algo-name> <digest-data>>))
;; =>
;; (sig-val (rsa (s <sig-data>)))
;; (sig-val (dsa (r <sig-data>) (s <sig-data>)))
;; (sig-val (elg (r <sig-data>) (s <sig-data>)))

(define (rsa-sign key digest digest-alg padding)
  (define data-sexp
    (gcry_sexp_build "(data (flags %s) (hash %s %b))"
                     padding
                     digest-alg
                     (cast (bytes-length digest) _uintptr _pointer)
                     digest))
  (define sig-sexp
    (gcry_pk_sign data-sexp key))
  (define sig-part
    (gcry_sexp_find_token sig-sexp "rsa"))
  (define sig-s-part
    (gcry_sexp_find_token sig-part "s"))
  (define sig-data
    (gcry_sexp_nth_data sig-s-part 1))
  (gcry_sexp_release sig-s-part)
  (gcry_sexp_release sig-part)
  (gcry_sexp_release sig-sexp)
  (gcry_sexp_release data-sexp)
  sig-data)

(define (rsa-verify key digest digest-alg padding sig)
  (define data-sexp
    (gcry_sexp_build "(data (flags %s) (hash %s %b))"
                     padding
                     digest-alg
                     (cast (bytes-length digest) _uintptr _pointer)
                     digest))
  (define sig-sexp
    (gcry_sexp_build "(sig-val (rsa (s %b)))"
                     (cast (bytes-length sig) _uintptr _pointer)
                     sig))
  (define result (gcry_pk_verify sig-sexp data-sexp key))
  (gcry_sexp_release sig-sexp)
  (gcry_sexp_release data-sexp)
  result)



(define key0
  #"(8:key-data(10:public-key(3:rsa(1:n257:\0\341<8\201\254\32\257\t\16\330\344\326\bg\254+\220\204\225\20\256\353\221j\355\332q\242\b\213{{-\320\311\32(\24-Q\325\234\5\357=\225)y\347LR\355\204\e\342R\333\360\376\32369\366\265\362\265Sh\b\e\21\363\t\260#\264\271+\300\21\371)O\366\am\262A\274\320\2\202\314\232X[\5\6\227\232/\37\226\352\357X\2\242b\371Vw\t**$\274\311\32\252m\277\361\345\204\377c}\3742\242\233\344\23\342C\202\213\317\35\241\374\231\277T\342.\234EI/\231Lje\4\237\226puZB\324=\362*p\342\346\303\227\376H\t\364S\234?RoR\206i\354\275\226\17\222\377~\24\211\357\34\205h6\\Y2o\342\300\230q\331=E\b{\r?9j\2046-8\254\336\4\306Z3 \316E\302XO\317=+\260~\313\350\246b \265c\0\30_\310`\362oA\252B~e\214\277)(1:e3:\1\0\1)))(11:private-key(3:rsa(1:n257:\0\341<8\201\254\32\257\t\16\330\344\326\bg\254+\220\204\225\20\256\353\221j\355\332q\242\b\213{{-\320\311\32(\24-Q\325\234\5\357=\225)y\347LR\355\204\e\342R\333\360\376\32369\366\265\362\265Sh\b\e\21\363\t\260#\264\271+\300\21\371)O\366\am\262A\274\320\2\202\314\232X[\5\6\227\232/\37\226\352\357X\2\242b\371Vw\t**$\274\311\32\252m\277\361\345\204\377c}\3742\242\233\344\23\342C\202\213\317\35\241\374\231\277T\342.\234EI/\231Lje\4\237\226puZB\324=\362*p\342\346\303\227\376H\t\364S\234?RoR\206i\354\275\226\17\222\377~\24\211\357\34\205h6\\Y2o\342\300\230q\331=E\b{\r?9j\2046-8\254\336\4\306Z3 \316E\302XO\317=+\260~\313\350\246b \265c\0\30_\310`\362oA\252B~e\214\277)(1:e3:\1\0\1)(1:d256:5=\232o\320\202X8\260iE\242pG-S\370\353\326\36\244\362k#\327\b\211N\317mE)\207Yp\207\375\314S0\"i\250\237v3\241\243\276\260ts\317\204\25\332\27B^\302\aq\351&\3661\265\177\4W}\3050\327\221\201!:=\303!\336\t\2303\6S\232%k\30\4\332\37k\336L\20TZ\256c\355\265(\21jA\377ZG\375\210M\216\273\263bh*\274\31\240\260\353\340\300\237\360\36\332\205\220\316\264\317\2\25\at\313\351\206j\257\330SW\305h\272\310\365@\344\262`\275b\36\1\257I\3666\225^\207\357\215_j\246 =\22\356\260v\206u\252\252mG\36#\352\223\363u\203}\214+\274\214=\0i\204\4\320\26s\336\365\373\374\266\235\32+:\36{\263\347L`\3\356\243\36\340\333\256\274MHt$&\327\301\346\201\217\241\211v\278\235*\2060 \341\346\213\303\242|A\321)(1:p129:\0\350\260v\177\4:\337\226\203\2275\200\342\367\374\271)\366\333\311r9 \251U\353\231\237\356Bc\266B\210l\24\220y\254[5\202\227)\365}4\21\246\342r9\255U=\2642W\217\374o\252\0020\256F\362\327\256\205p\327q\24o\337/U\375\3jC\35_\311\272\252\302N\260\2130sJ]\267\243o\v\220J\303\250\250_T\242]\333\325\351\2767\211\276C\4D\325\334\351E\233pY\300N\321)(1:q129:\0\367\314\227V{\352U\317z?\322t\34\346\214r!s9=\2561\354k\340Z\237&\242%G\20\320\"\332\0303\362\211;\215\e\264\326\202\347\205D\245\317\357\353\3\254;\372\204\20\266\3747\377\24=\332}\270K\325\370B\341RMbOs\37{\210uQ&3\365\nZ\273l\332\336[\201\343\351\215q\330;B\373\220WR\17\302!\246I1\363cr\254\263\255e\264;t\316\241j\34~~\246\217)(1:u129:\0\316\315\2B\226\342\334\254\177s\342\26\365\344+\265\3046\232\f\310\217\30t\231\223\v\325w\313\16\363;\213\207\364\2163\242\254\227\266A\25\236\3550F\365m2\222\230e\274\37Y\314J\371\270[qo+\226C\232Z\277<\22\244\17\271\205\234\3640\320\177\332\275H;_\375Ap \4\243+\327.\301E\223\256\237E\36\271\262\e\346f_|C\243Uv=Em\373\304\203\321o.\303\236g]\223\257))))\0")

