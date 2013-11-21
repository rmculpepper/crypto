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
(require racket/class
         (only-in racket/contract/base or/c)
         ffi/unsafe
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "ffi.rkt"
         (only-in "../common/common.rkt" shrink-bytes))
(provide (all-defined-out))

#|
References:
 - http://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman

params = EC_KEY_new_by_curve_name(NID)

EC_KEY_generate_key

group = EC_KEY_get0_group(key)  ;; really the params? maybe not...
fieldsize = EC_GROUP_get_degree(group)

secret is fieldsize bits long (round up to multiple of 8)

peerpubkey = EC_KEY_get0_public_key(EC_KEY peerkey)

secret = ECDH_compute_key(key, peerpubkey)

|#

#|
;; Enumerate and describe all builtin curves.
;; Is there a standard, canonical name for curves?
;; Maybe NID => SN (short name) using OBJ_??? ?
(define curve-count (EC_get_builtin_curves #f 0))
(define ci0 (malloc curve-count _EC_builtin_curve 'atomic))
(set! ci0 (cast ci0 _pointer _EC_builtin_curve-pointer))
(EC_get_builtin_curves ci0 curve-count)
(for/list ([i curve-count])
  (define ci (ptr-add ci0 i _EC_builtin_curve))
  (list (EC_builtin_curve-nid ci) (EC_builtin_curve-comment ci)))
|#

(require "dh.rkt")

(define allowed-ec-paramgen
  `((curve-nid ,exact-nonnegative-integer? "exact-nonnegative-integer?")))

(define libcrypto-ec-impl%
  (class* impl-base% ( #| key-agree-impl<%> |# )
    (super-new (spec 'ecdh))

    (define/public (generate-params who config)
      (check-keygen-spec who config allowed-ec-paramgen)
      (let ([curve-nid (keygen-spec-ref config 'curve-nid)])
        (unless curve-nid
          (error who "missing required configuration key\n  key: ~s" 'curve-nid))
        (define group (EC_GROUP_new_by_curve_name curve-nid))
        (unless group
          (error who "named curve not found\n  curve NID: ~e" curve-nid))
        (new libcrypto-ec-curve% (impl this) (group group))))

    (define/public (read-params who buf fmt)
      (unless (eq? fmt #f)
        (error who "bad EC parameters format\n  format: ~e" fmt))
      (define group (d2i_ECPKParameters buf (bytes-length buf)))
      ;; FIXME: check?
      (new libcrypto-ec-curve% (impl this) (group group)))

    (define/public (read-params+key who bufs fmt)
      (define params (read-params who (car bufs) fmt))
      (send params read-key who (cdr bufs) fmt))

    ))

(define allowed-ec-keygen '())

(define libcrypto-ec-curve%
  (class* ctx-base% ( #| key-agree-params<%> |# )
    (init-field group)
    (inherit-field impl)
    (super-new)

    (define/public (write-params who fmt)
      (unless (eq? fmt #f)
        (error who "bad EC parameters format\n  format: ~e" fmt))
      (define len (i2d_ECPKParameters group #f))
      (define buf (make-bytes len))
      (define len2 (i2d_ECPKParameters group buf))
      (shrink-bytes buf len2))

    (define/public (generate-key who config)
      (check-keygen-spec who config allowed-ec-keygen)
      (define ec (EC_KEY_new))
      (EC_KEY_set_group ec group)
      (EC_KEY_generate_key ec)
      (new libcrypto-ec-key% (impl impl) (ec ec) (curve this)))

    (define/public (read-key who bufs fmt)
      (unless (eq? fmt #f)
        (error who "bad EC key format\n  format: ~e" fmt))
      (define pubkeybuf (car bufs))
      (define pubkey (EC_POINT_new group))
      (EC_POINT_oct2point group pubkey pubkeybuf (bytes-length pubkeybuf))
      (define privkeybuf (cadr bufs))
      (define privkey (BN_bin2bn privkeybuf))
      (define ec (EC_KEY_new))
      (EC_KEY_set_group ec group)
      (EC_KEY_set_private_key ec privkey)
      (EC_KEY_set_public_key ec pubkey)
      (EC_POINT_free pubkey)
      (BN_free privkey)
      (new libcrypto-ec-key% (impl impl) (ec ec) (curve this)))

    (define/public (get-degree)
      (EC_GROUP_get_degree group))
    ))

(define libcrypto-ec-key%
  (class* ctx-base% ()
    (init-field ec [curve #f])
    (inherit-field impl)
    (super-new)

    (define/public (get-params who)
      (unless curve
        (define group (EC_GROUP_dup (EC_KEY_get0_group ec)))
        (set! curve (new libcrypto-ec-curve% (impl impl) (group group))))
      curve)

    (define/public (compute-secret peer-pubkey)
      (define group (EC_KEY_get0_group ec))
      (define group-degree (EC_GROUP_get_degree group))
      (define buf (make-bytes (quotient (+ group-degree 7) 8)))
      (define peer-pubkey-point (EC_POINT_new group))
      (EC_POINT_oct2point group peer-pubkey-point peer-pubkey (bytes-length peer-pubkey))
      (ECDH_compute_key buf (bytes-length buf) peer-pubkey-point ec)
      (EC_POINT_free peer-pubkey-point)
      buf)

    (define/public (write-key who private? fmt)
      (unless (eq? fmt #f)
        (error "bad EC key format\n  format: ~e" fmt))
      (define group (EC_KEY_get0_group ec))
      (define pubkey (EC_KEY_get0_public_key ec))
      (define pubkey-len (EC_POINT_point2oct group pubkey POINT_CONVERSION_COMPRESSED #f 0))
      (define pubkeybuf (make-bytes pubkey-len))
      (EC_POINT_point2oct group pubkey POINT_CONVERSION_COMPRESSED pubkeybuf pubkey-len)
      (define privkey (and private? (EC_KEY_get0_private_key ec)))
      (list* (send (get-params who) write-params who fmt)
             pubkeybuf
             (if private?
                 (list (BN->bytes/bin (EC_KEY_get0_private_key ec)))
                 null)))

    ))
