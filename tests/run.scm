(use srfi-13)

(use test json hpack)

(define (get-string seq)
  (hex-string->string (cdr (vector-ref seq 1))))

(define (get-header-list seq)
  (map
    (lambda (x)
      (cons (string->symbol (car x)) (cdr x)))
    (map (compose car vector->list) (cdr (vector-ref seq 2)))))

(define (hex-string->bytes s)
  (if (string-null? s)
    '()
    (cons (string->number (string-take s 2) 16) (hex-string->bytes (string-drop s 2)))))

(define (hex-string->string s)
  (list->string
    (map integer->char
         (hex-string->bytes s))))

(define (header-eq? a b)
  (and (eq? (car a) (car b))
       (string=? (cdr a) (cdr b))))

(define (header-list-eq? hl-a hl-b)
  (and (eq? (length hl-a) (length hl-b))
       (every header-eq? hl-a hl-b)))

(define decode (make-hpack-decoder))
(define encode (make-hpack-encoder))
(define de-encode (make-hpack-decoder))

(define dht (make-header-table))
(define eht (make-header-table))
(define bis (make-header-table))

(for-each 
    (lambda (n)
      (let* ((file-name (conc "./tests/story_"
                              (string-pad (number->string n) 2 #\0)
                              ".json"))
             (struct (with-input-from-file file-name json-read))
             (strings (map get-string (cdr (vector-ref struct 0))))
             (header-lists (map get-header-list (cdr (vector-ref struct 0)))))
        (test-group (conc "story " n)
                    (let lp ((seq 0)
			     (d (map (lambda (s)
				       (hpack-decode dht s))
				     strings))
			     (hls header-lists))
                      (if (null? d)
                        '()
                        (begin
                          (test-assert (conc "decode seq " seq)
				       (header-list-eq? (car d)
							(car hls)))
			  
                          (test-assert (conc "encode seq " seq)
				       (header-list-eq? (hpack-decode bis
								      (hpack-encode eht
										    (car hls)))
							(car hls)))
                          (lp (+ seq 1) (cdr d) (cdr hls))))))))
  (iota 32))

