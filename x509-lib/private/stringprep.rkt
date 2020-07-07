#lang racket/base
(require racket/string)
(provide ldap-stringprep
         ldap-string=?
         ldap-string-ci=?)

;; ============================================================

(module intset racket/base
  (require (for-syntax racket/base syntax/parse racket/match))
  (provide intset
           char-predicate
           int-in-set?
           char-in-set?)
  (define-syntax (intset stx)
    (define-syntax-class range
      (pattern [lo:nat hi:nat])
      (pattern lo:nat #:with hi #'lo))
    (syntax-parse stx
      [(_ r:range ...)
       (define ranges0 (syntax->datum #'((r.lo r.hi) ...)))
       (define (compress ranges)
         (match ranges
           [(list* (list lo1 hi1) (list lo2 hi2) more)
            (cond [(>= (add1 hi1) lo2)
                   (compress (list* (list lo1 (max hi1 hi2)) more))]
                  [else
                   (cons (car ranges) (compress (cdr ranges)))])]
           [else ranges]))
       #`(quote #,(list->vector (apply append (compress (sort ranges0 < #:key car)))))]))
  (define ((char-predicate . sets) c)
    (for/or ([s (in-list sets)]) (char-in-set? c s)))
  (define (char-in-set? c is) (int-in-set? (char->integer c) is))

  ;; An IntSet is (Vector {lo hi} ...)
  ;; Intepretation: (lambda (x) (or (<= lo x hi) ...))
  (define (int-in-set? seek is)
    ;; (eprintf "seeking ~s\n" seek)
    (define (value k) (vector-ref is k))
    (define (loop lo hi)
      ;; (eprintf "  loop ~s, ~s\n" lo hi)
      (and (< lo hi) (loop* lo hi)))
    (define (loop* lo hi)
      ;; INV: (<= (value lo) seek (value hi))
      ;; INV: (even? lo) and (odd? hi)
      (define midlo (* 2 (quotient (+ lo hi 1) 4)))
      (define midhi (add1 midlo))
      (cond [(< seek (value midlo))
             (loop lo (sub1 midlo))]
            [(< (value midhi) seek)
             (loop (add1 midhi) hi)]
            ;; (value midlo) <= seek <= (value midhi)
            [else #t]))
    (let ([last (sub1 (vector-length is))])
      (cond [(<= (value 0) seek (value last))
             (loop 0 last)]
            [else #f]))))
(require (submod "." intset))

;; ============================================================

;; References:
;; - https://tools.ietf.org/html/rfc3454 (stringprep framework)
;; - https://tools.ietf.org/html/rfc4518 (LDAP profile)

;; ldap-stringprep : String #:on-error (U #f (String -> X)) -> (U String X)
(define (ldap-stringprep orig
                         #:on-error [handle #f]
                         #:who [who 'ldap-stringprep])
  (let* ([s (do-mapping orig)]
         [s (string-normalize-nfkc s)]
         [s (and (do-prohibit who s orig (not handle)) s)])
    (cond [s (do-insignificant-character-handling s)]
          [else (handle orig)])))

(define (ldap-string-cmp who s1 s2 string-cmp)
  (define (convert s) (ldap-stringprep s #:on-error (lambda (x) #f) #:who who))
  (let ([s1 (convert s1)] [s2 (convert s2)])
    (and s1 s2 (string-cmp s1 s2))))

(define (ldap-string=? s1 s2)
  (ldap-string-cmp 'ldap-string=? s1 s2 string=?))
(define (ldap-string-ci=? s1 s2)
  (ldap-string-cmp 'ldap-string-ci=? s1 s2 string-ci=?))

;; 2.2 Map

(define (do-mapping s)
  (define out (open-output-string))
  (for ([c (in-string s)])
    (cond [(map-to-space? c) (write-char #\space out)]
          [(map-to-nothing? c) (void)]
          [else (write-char c out)]))
  (get-output-string out))

(define mapped-to-nothing
  (intset
   ;; para 1
   #x00AD
   #x1806
   #x034F
   [#x180B #x180D]
   [#xFE00 #xFE0F]
   #xFFFC
   ;; para 3
   [#x0000 #x0008]
   [#x000E #x001F]
   [#x007F #x0084]
   [#x0086 #x009F]
   #x06DD
   #x070F
   #x180E
   [#x200C #x200F]
   [#x202A #x202E]
   [#x2060 #x2063]
   [#x206A #x206F]
   #xFEFF
   [#xFFF9 #xFFFB]
   [#x1D173 #x1D17A]
   #xE0001
   [#xE0020 #xE007F]
   ;; para 4
   #x200B))

(define mapped-to-space
  (intset
   ;; para 2
   #x0009
   #x000A
   #x000B
   #x000C
   #x000D
   #x0085
   ;; para 4
   #x00A0
   #x1680
   [#x2000 #x200A]
   [#x2028 #x2029]
   #x202F
   #x205F
   #x3000))

(define map-to-nothing? (char-predicate mapped-to-nothing))
(define map-to-space?   (char-predicate mapped-to-space))

;; 2.3 Normalize (KC)

;; 2.4 Prohibit

;; returns #t if okay, #f (or error) if contains prohibited char
(define (do-prohibit who s orig error?)
  (define (bad c msg)
    (if error? (error who "~a\n  string: ~e\n  char: ~e" msg orig c) #f))
  (for/and ([c (in-string s)])
    (cond [(prohibited-char? c) (bad c "prohibited character in string")]
          [(unassigned-char? c) (bad c "unassigned character in string")]
          [else #t])))

;; A.1 Unassigned code points in Unicode 3.2
(define unassigned-in-unicode-3.2
  (intset
   #x0221
   [#x0234 #x024F]
   [#x02AE #x02AF]
   [#x02EF #x02FF]
   [#x0350 #x035F]
   [#x0370 #x0373]
   [#x0376 #x0379]
   [#x037B #x037D]
   [#x037F #x0383]
   #x038B
   #x038D
   #x03A2
   #x03CF
   [#x03F7 #x03FF]
   #x0487
   #x04CF
   [#x04F6 #x04F7]
   [#x04FA #x04FF]
   [#x0510 #x0530]
   [#x0557 #x0558]
   #x0560
   #x0588
   [#x058B #x0590]
   #x05A2
   #x05BA
   [#x05C5 #x05CF]
   [#x05EB #x05EF]
   [#x05F5 #x060B]
   [#x060D #x061A]
   [#x061C #x061E]
   #x0620
   [#x063B #x063F]
   [#x0656 #x065F]
   [#x06EE #x06EF]
   #x06FF
   #x070E
   [#x072D #x072F]
   [#x074B #x077F]
   [#x07B2 #x0900]
   #x0904
   [#x093A #x093B]
   [#x094E #x094F]
   [#x0955 #x0957]
   [#x0971 #x0980]
   #x0984
   [#x098D #x098E]
   [#x0991 #x0992]
   #x09A9
   #x09B1
   [#x09B3 #x09B5]
   [#x09BA #x09BB]
   #x09BD
   [#x09C5 #x09C6]
   [#x09C9 #x09CA]
   [#x09CE #x09D6]
   [#x09D8 #x09DB]
   #x09DE
   [#x09E4 #x09E5]
   [#x09FB #x0A01]
   [#x0A03 #x0A04]
   [#x0A0B #x0A0E]
   [#x0A11 #x0A12]
   #x0A29
   #x0A31
   #x0A34
   #x0A37
   [#x0A3A #x0A3B]
   #x0A3D
   [#x0A43 #x0A46]
   [#x0A49 #x0A4A]
   [#x0A4E #x0A58]
   #x0A5D
   [#x0A5F #x0A65]
   [#x0A75 #x0A80]
   #x0A84
   #x0A8C
   #x0A8E
   #x0A92
   #x0AA9
   #x0AB1
   #x0AB4
   [#x0ABA #x0ABB]
   #x0AC6
   #x0ACA
   [#x0ACE #x0ACF]
   [#x0AD1 #x0ADF]
   [#x0AE1 #x0AE5]
   [#x0AF0 #x0B00]
   #x0B04
   [#x0B0D #x0B0E]
   [#x0B11 #x0B12]
   #x0B29
   #x0B31
   [#x0B34 #x0B35]
   [#x0B3A #x0B3B]
   [#x0B44 #x0B46]
   [#x0B49 #x0B4A]
   [#x0B4E #x0B55]
   [#x0B58 #x0B5B]
   #x0B5E
   [#x0B62 #x0B65]
   [#x0B71 #x0B81]
   #x0B84
   [#x0B8B #x0B8D]
   #x0B91
   [#x0B96 #x0B98]
   #x0B9B
   #x0B9D
   [#x0BA0 #x0BA2]
   [#x0BA5 #x0BA7]
   [#x0BAB #x0BAD]
   #x0BB6
   [#x0BBA #x0BBD]
   [#x0BC3 #x0BC5]
   #x0BC9
   [#x0BCE #x0BD6]
   [#x0BD8 #x0BE6]
   [#x0BF3 #x0C00]
   #x0C04
   #x0C0D
   #x0C11
   #x0C29
   #x0C34
   [#x0C3A #x0C3D]
   #x0C45
   #x0C49
   [#x0C4E #x0C54]
   [#x0C57 #x0C5F]
   [#x0C62 #x0C65]
   [#x0C70 #x0C81]
   #x0C84
   #x0C8D
   #x0C91
   #x0CA9
   #x0CB4
   [#x0CBA #x0CBD]
   #x0CC5
   #x0CC9
   [#x0CCE #x0CD4]
   #x0CD7 #x0CDD
   #x0CDF
   [#x0CE2 #x0CE5]
   [#x0CF0 #x0D01]
   #x0D04
   #x0D0D
   #x0D11
   #x0D29
   [#x0D3A #x0D3D]
   [#x0D44 #x0D45]
   #x0D49
   [#x0D4E #x0D56]
   [#x0D58 #x0D5F]
   [#x0D62 #x0D65]
   [#x0D70 #x0D81]
   #x0D84
   [#x0D97 #x0D99]
   #x0DB2
   #x0DBC
   [#x0DBE #x0DBF]
   [#x0DC7 #x0DC9]
   [#x0DCB #x0DCE]
   #x0DD5
   #x0DD7
   [#x0DE0 #x0DF1]
   [#x0DF5 #x0E00]
   [#x0E3B #x0E3E]
   [#x0E5C #x0E80]
   #x0E83
   [#x0E85 #x0E86]
   #x0E89
   [#x0E8B #x0E8C]
   [#x0E8E #x0E93]
   #x0E98
   #x0EA0
   #x0EA4
   #x0EA6
   [#x0EA8 #x0EA9]
   #x0EAC
   #x0EBA
   [#x0EBE #x0EBF]
   #x0EC5
   #x0EC7
   [#x0ECE #x0ECF]
   [#x0EDA #x0EDB]
   [#x0EDE #x0EFF]
   #x0F48
   [#x0F6B #x0F70]
   [#x0F8C #x0F8F]
   #x0F98
   #x0FBD
   [#x0FCD #x0FCE]
   [#x0FD0 #x0FFF]
   #x1022
   #x1028
   #x102B
   [#x1033 #x1035]
   [#x103A #x103F]
   [#x105A #x109F]
   [#x10C6 #x10CF]
   [#x10F9 #x10FA]
   [#x10FC #x10FF]
   [#x115A #x115E]
   [#x11A3 #x11A7]
   [#x11FA #x11FF]
   #x1207
   #x1247
   #x1249
   [#x124E #x124F]
   #x1257
   #x1259
   [#x125E #x125F]
   #x1287
   #x1289
   [#x128E #x128F]
   #x12AF
   #x12B1
   [#x12B6 #x12B7]
   #x12BF
   #x12C1
   [#x12C6 #x12C7]
   #x12CF
   #x12D7
   #x12EF
   #x130F
   #x1311
   [#x1316 #x1317]
   #x131F
   #x1347
   [#x135B #x1360]
   [#x137D #x139F]
   [#x13F5 #x1400]
   [#x1677 #x167F]
   [#x169D #x169F]
   [#x16F1 #x16FF]
   #x170D
   [#x1715 #x171F]
   [#x1737 #x173F]
   [#x1754 #x175F]
   #x176D
   #x1771
   [#x1774 #x177F]
   [#x17DD #x17DF]
   [#x17EA #x17FF]
   #x180F
   [#x181A #x181F]
   [#x1878 #x187F]
   [#x18AA #x1DFF]
   [#x1E9C #x1E9F]
   [#x1EFA #x1EFF]
   [#x1F16 #x1F17]
   [#x1F1E #x1F1F]
   [#x1F46 #x1F47]
   [#x1F4E #x1F4F]
   #x1F58
   #x1F5A
   #x1F5C
   #x1F5E
   [#x1F7E #x1F7F]
   #x1FB5
   #x1FC5
   [#x1FD4 #x1FD5]
   #x1FDC
   [#x1FF0 #x1FF1]
   #x1FF5
   #x1FFF
   [#x2053 #x2056]
   [#x2058 #x205E]
   [#x2064 #x2069]
   [#x2072 #x2073]
   [#x208F #x209F]
   [#x20B2 #x20CF]
   [#x20EB #x20FF]
   [#x213B #x213C]
   [#x214C #x2152]
   [#x2184 #x218F]
   [#x23CF #x23FF]
   [#x2427 #x243F]
   [#x244B #x245F]
   #x24FF
   [#x2614 #x2615]
   #x2618
   [#x267E #x267F]
   [#x268A #x2700]
   #x2705
   [#x270A #x270B]
   #x2728
   #x274C
   #x274E
   [#x2753 #x2755]
   #x2757
   [#x275F #x2760]
   [#x2795 #x2797]
   #x27B0
   [#x27BF #x27CF]
   [#x27EC #x27EF]
   [#x2B00 #x2E7F]
   #x2E9A
   [#x2EF4 #x2EFF]
   [#x2FD6 #x2FEF]
   [#x2FFC #x2FFF]
   #x3040
   [#x3097 #x3098]
   [#x3100 #x3104]
   [#x312D #x3130]
   #x318F
   [#x31B8 #x31EF]
   [#x321D #x321F]
   [#x3244 #x3250]
   [#x327C #x327E]
   [#x32CC #x32CF]
   #x32FF
   [#x3377 #x337A]
   [#x33DE #x33DF]
   #x33FF
   [#x4DB6 #x4DFF]
   [#x9FA6 #x9FFF]
   [#xA48D #xA48F]
   [#xA4C7 #xABFF]
   [#xD7A4 #xD7FF]
   [#xFA2E #xFA2F]
   [#xFA6B #xFAFF]
   [#xFB07 #xFB12]
   [#xFB18 #xFB1C]
   #xFB37
   #xFB3D
   #xFB3F
   #xFB42
   #xFB45
   [#xFBB2 #xFBD2]
   [#xFD40 #xFD4F]
   [#xFD90 #xFD91]
   [#xFDC8 #xFDCF]
   [#xFDFD #xFDFF]
   [#xFE10 #xFE1F]
   [#xFE24 #xFE2F]
   [#xFE47 #xFE48]
   #xFE53
   #xFE67
   [#xFE6C #xFE6F]
   #xFE75
   [#xFEFD #xFEFE]
   #xFF00
   [#xFFBF #xFFC1]
   [#xFFC8 #xFFC9]
   [#xFFD0 #xFFD1]
   [#xFFD8 #xFFD9]
   [#xFFDD #xFFDF]
   #xFFE7
   [#xFFEF #xFFF8]
   [#x10000 #x102FF]
   #x1031F
   [#x10324 #x1032F]
   [#x1034B #x103FF]
   [#x10426 #x10427]
   [#x1044E #x1CFFF]
   [#x1D0F6 #x1D0FF]
   [#x1D127 #x1D129]
   [#x1D1DE #x1D3FF]
   #x1D455
   #x1D49D
   [#x1D4A0 #x1D4A1]
   [#x1D4A3 #x1D4A4]
   [#x1D4A7 #x1D4A8]
   #x1D4AD
   #x1D4BA
   #x1D4BC
   #x1D4C1
   #x1D4C4
   #x1D506
   [#x1D50B #x1D50C]
   #x1D515
   #x1D51D
   #x1D53A
   #x1D53F
   #x1D545
   [#x1D547 #x1D549]
   #x1D551
   [#x1D6A4 #x1D6A7]
   [#x1D7CA #x1D7CD]
   [#x1D800 #x1FFFD]
   [#x2A6D7 #x2F7FF]
   [#x2FA1E #x2FFFD]
   [#x30000 #x3FFFD]
   [#x40000 #x4FFFD]
   [#x50000 #x5FFFD]
   [#x60000 #x6FFFD]
   [#x70000 #x7FFFD]
   [#x80000 #x8FFFD]
   [#x90000 #x9FFFD]
   [#xA0000 #xAFFFD]
   [#xB0000 #xBFFFD]
   [#xC0000 #xCFFFD]
   [#xD0000 #xDFFFD]
   #xE0000
   [#xE0002 #xE001F]
   [#xE0080 #xEFFFD]
   ))

(define unassigned-char? (char-predicate unassigned-in-unicode-3.2))

;; C.3 Private use
(define private-use
  (intset
   [#xE000 #xF8FF]; [PRIVATE USE, PLANE 0]
   [#xF0000 #xFFFFD]; [PRIVATE USE, PLANE 15]
   [#x100000 #x10FFFD]; [PRIVATE USE, PLANE 16]
   ))

;; C.4 Non-character code points
(define non-character-code-points
  (intset
   [#xFDD0 #xFDEF]; [NONCHARACTER CODE POINTS]
   [#xFFFE #xFFFF]; [NONCHARACTER CODE POINTS]
   [#x1FFFE #x1FFFF]; [NONCHARACTER CODE POINTS]
   [#x2FFFE #x2FFFF]; [NONCHARACTER CODE POINTS]
   [#x3FFFE #x3FFFF]; [NONCHARACTER CODE POINTS]
   [#x4FFFE #x4FFFF]; [NONCHARACTER CODE POINTS]
   [#x5FFFE #x5FFFF]; [NONCHARACTER CODE POINTS]
   [#x6FFFE #x6FFFF]; [NONCHARACTER CODE POINTS]
   [#x7FFFE #x7FFFF]; [NONCHARACTER CODE POINTS]
   [#x8FFFE #x8FFFF]; [NONCHARACTER CODE POINTS]
   [#x9FFFE #x9FFFF]; [NONCHARACTER CODE POINTS]
   [#xAFFFE #xAFFFF]; [NONCHARACTER CODE POINTS]
   [#xBFFFE #xBFFFF]; [NONCHARACTER CODE POINTS]
   [#xCFFFE #xCFFFF]; [NONCHARACTER CODE POINTS]
   [#xDFFFE #xDFFFF]; [NONCHARACTER CODE POINTS]
   [#xEFFFE #xEFFFF]; [NONCHARACTER CODE POINTS]
   [#xFFFFE #xFFFFF]; [NONCHARACTER CODE POINTS]
   [#x10FFFE #x10FFFF]; [NONCHARACTER CODE POINTS]
   ))

;; C.5 Surrogate codes
(define surrogate-codes
  (intset
   [#xD800 #xDFFF]; [SURROGATE CODES]
   ))

;; C.8 Change display properties or are deprecated
(define change-display-properties-or-deprecated
  (intset
   #x0340; COMBINING GRAVE TONE MARK
   #x0341; COMBINING ACUTE TONE MARK
   #x200E; LEFT-TO-RIGHT MARK
   #x200F; RIGHT-TO-LEFT MARK
   #x202A; LEFT-TO-RIGHT EMBEDDING
   #x202B; RIGHT-TO-LEFT EMBEDDING
   #x202C; POP DIRECTIONAL FORMATTING
   #x202D; LEFT-TO-RIGHT OVERRIDE
   #x202E; RIGHT-TO-LEFT OVERRIDE
   #x206A; INHIBIT SYMMETRIC SWAPPING
   #x206B; ACTIVATE SYMMETRIC SWAPPING
   #x206C; INHIBIT ARABIC FORM SHAPING
   #x206D; ACTIVATE ARABIC FORM SHAPING
   #x206E; NATIONAL DIGIT SHAPES
   #x206F; NOMINAL DIGIT SHAPES
   ))

(define (prohibited-char? c)
  (or (char-in-set? c private-use)
      (char-in-set? c non-character-code-points)
      (char-in-set? c surrogate-codes)
      (char-in-set? c change-display-properties-or-deprecated)
      (char=? c #\uFFFD)))

;; 2.5 Check Bidi -- nothing to do

;; 2.6 Insignificant Character Handling

;; Per Appendix B, since we don't care about LDAP "substrings
;; matching", can simplify to trim/collapse space.

;; From 2.6:
;;   For the purposes of this section, a space is defined to be the
;;   SPACE (U+0020) code point followed by no combining marks.

(define (do-insignificant-character-handling s)
  ;; M = Mn + Mc + Me
  (cond [(regexp-match? #rx"^[ ]+$" s) " "]
        [else (let* ([rx #px"[ ]+(?!\\p{M})"]
                     [s (string-trim s rx)])
                (regexp-replace* rx s " "))]))
