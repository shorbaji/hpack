
(use srfi-13)

(use test json hpack)

(define (get-wire seq)
  (cdr (vector-ref seq 1)))

(define (get-header-list seq)
  (map
    (lambda (x)
      (cons (string->symbol (car x)) (cdr x)))
    (map (compose car vector->list) (cdr (vector-ref seq 2)))))

(define (hex-string->bytes s)
  (if (string-null? s)
    '()
    (cons (string->number (string-take s 2) 16) (hex-string->bytes (string-drop s 2)))))

(define (header-eq? a b)
  (and (eq? (car a) (car b))
       (string=? (cdr a) (cdr b))))

(define (header-list-eq? hl-a hl-b)
  (and (eq? (length hl-a) (length hl-b))
       (every header-eq? hl-a hl-b)))

(test make-hpack-encoder make-hpack-encoder)

(test make-hpack-decoder make-hpack-decoder)

(define decode (make-hpack-decoder))

(test-group "decoder"
  (for-each 
    (lambda (n)
      (display (conc "test " n ": "))
      (let* ((file-name (conc "./hpack-test-case/nghttp2/story_"
                              (string-pad (number->string n) 2 #\0)
                              ".json"))
             (struct (with-input-from-file file-name json-read))
             (wires (map get-wire (cdr (vector-ref struct 0))))
             (header-lists (map get-header-list (cdr (vector-ref struct 0))))
             (success (every identity
                             (map header-list-eq?
                                  header-lists
                                  (map (compose decode
                                                hex-string->bytes)
                                       wires)))))
        (test-assert success)))
    (iota 30)))

(test-exit)
