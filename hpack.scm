;;
;; hpack is a HTTP/2 header compression library for Chicken
;; Copyright (c) 2014, Omar Shorbaji
;; All rights reserved.
;;
;; Redistribution and use in source and binary forms, with or without
;; modification, are permitted provided that the following conditions are met:
;;
;; Redistributions of source code must retain the above copyright notice, this
;; list of conditions and the following disclaimer. 
;; Redistributions in binary form must reproduce the above copyright notice,
;; this list of conditions and the following disclaimer in the documentation
;; and/or other materials provided with the distribution. 
;; Neither the name of the author nor the names of its contributors may be
;; used to endorse or promote products derived from this software without
;; specific prior written permission. 
;;
;; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
;; AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
;; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
;; ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
;; LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
;; CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OFcl
;; SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
;; INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
;; CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
;; ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
;; POSSIBILITY OF SUCH DAMAGE.

;; Implements draft 9 of HPACK - Header Compression for HTTP/2
;; draft-ietf-httpbis-header-compression-09
;; reference: http://tools.ietf.org/html/draft-ietf-httpbis-header-compression-09 

;; TODOs: 
;; 1. optimize for performance - particularly looking at huffman encoding/decoding
;; 2. error & exception handling

(module hpack
  (make-hpack-encoder make-hpack-decoder)

  (import chicken scheme)
  (use srfi-1 defstruct)

  (define make-error '())

  (define SETTINGS-HEADER-TABLE-SIZE (* 256 256 256)) ; arbitrary - should make a parameter

  ;; The Huffman code - copied directly from Appendix C and used to encode 

  (define huffman-code
    '(
      (1 1 1 1 1 1 1 1 1 1 0 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 0 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1)
      (0 1 0 1 0 0)
      (1 1 1 1 1 1 1 0 0 0)
      (1 1 1 1 1 1 1 0 0 1)
      (1 1 1 1 1 1 1 1 1 0 1 0)
      (1 1 1 1 1 1 1 1 1 1 0 0 1)
      (0 1 0 1 0 1)
      (1 1 1 1 1 0 0 0)
      (1 1 1 1 1 1 1 1 0 1 0)
      (1 1 1 1 1 1 1 0 1 0)
      (1 1 1 1 1 1 1 0 1 1)
      (1 1 1 1 1 0 0 1)
      (1 1 1 1 1 1 1 1 0 1 1)
      (1 1 1 1 1 0 1 0)
      (0 1 0 1 1 0)
      (0 1 0 1 1 1)
      (0 1 1 0 0 0)
      (0 0 0 0 0)
      (0 0 0 0 1)
      (0 0 0 1 0)
      (0 1 1 0 0 1)
      (0 1 1 0 1 0)
      (0 1 1 0 1 1)
      (0 1 1 1 0 0)
      (0 1 1 1 0 1)
      (0 1 1 1 1 0)
      (0 1 1 1 1 1)
      (1 0 1 1 1 0 0)
      (1 1 1 1 1 0 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 0 0)
      (1 0 0 0 0 0)
      (1 1 1 1 1 1 1 1 1 0 1 1)
      (1 1 1 1 1 1 1 1 0 0)
      (1 1 1 1 1 1 1 1 1 1 0 1 0)
      (1 0 0 0 0 1)
      (1 0 1 1 1 0 1)
      (1 0 1 1 1 1 0)
      (1 0 1 1 1 1 1)
      (1 1 0 0 0 0 0)
      (1 1 0 0 0 0 1)
      (1 1 0 0 0 1 0)
      (1 1 0 0 0 1 1)
      (1 1 0 0 1 0 0)
      (1 1 0 0 1 0 1)
      (1 1 0 0 1 1 0)
      (1 1 0 0 1 1 1)
      (1 1 0 1 0 0 0)
      (1 1 0 1 0 0 1)
      (1 1 0 1 0 1 0)
      (1 1 0 1 0 1 1)
      (1 1 0 1 1 0 0)
      (1 1 0 1 1 0 1)
      (1 1 0 1 1 1 0)
      (1 1 0 1 1 1 1)
      (1 1 1 0 0 0 0)
      (1 1 1 0 0 0 1)
      (1 1 1 0 0 1 0)
      (1 1 1 1 1 1 0 0)
      (1 1 1 0 0 1 1)
      (1 1 1 1 1 1 0 1)
      (1 1 1 1 1 1 1 1 1 1 0 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 0 0)
      (1 0 0 0 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 0 1)
      (0 0 0 1 1)
      (1 0 0 0 1 1)
      (0 0 1 0 0)
      (1 0 0 1 0 0)
      (0 0 1 0 1)
      (1 0 0 1 0 1)
      (1 0 0 1 1 0)
      (1 0 0 1 1 1)
      (0 0 1 1 0)
      (1 1 1 0 1 0 0)
      (1 1 1 0 1 0 1)
      (1 0 1 0 0 0)
      (1 0 1 0 0 1)
      (1 0 1 0 1 0)
      (0 0 1 1 1)
      (1 0 1 0 1 1)
      (1 1 1 0 1 1 0)
      (1 0 1 1 0 0)
      (0 1 0 0 0)
      (0 1 0 0 1)
      (1 0 1 1 0 1)
      (1 1 1 0 1 1 1)
      (1 1 1 1 0 0 0)
      (1 1 1 1 0 0 1)
      (1 1 1 1 0 1 0)
      (1 1 1 1 0 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 0)
      (1 1 1 1 1 1 1 1 1 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 0 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 0 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 1 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 1 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 0 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 1 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 0 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 0 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 1 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 1 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 1 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 1 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 1 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 1 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 0 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 0 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 0 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 1 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 0 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 1 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 1 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 1 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 1 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 1 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 1 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 1 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 1 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 1 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 0 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 0 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 1 1)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 1 0)
      (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1)))

  ; Naive implementation of Huffman decoding 
  ; We convert the input to a bit stream
  ; We traverse a tree going left if 0, right is 1 and return the leaf

  (define huffman-tree
    '(((((48 . 49) 50 . 97) (99 . 101) 105 . 111)
       ((115 . 116) (32 . 37) 45 . 46) ((47 . 51) 52 . 53)
       (54 . 55) 56 . 57) ((((61 . 65) 95 . 98) (100 . 102) 103 . 104)
       ((108 . 109) 110 . 112) (114 . 117) (58 . 66) 67 . 68)
      ((((69 . 70) 71 . 72) (73 . 74) 75 . 76) ((77 . 78) 79 . 80) (81 . 82) 83 . 84)
      (((85 . 86) 87 . 89) (106 . 107) 113 . 118) ((119 . 120) 121 . 122)
      ((38 . 42) 44 . 59) (88 . 90) ((33 . 34) 40 . 41) (63 39 . 43)
      (124 35 . 62) ((0 . 36) 64 . 91) (93 . 126) (94 . 125) (60 . 96) 123
      (((92 . 195) 208 128 . 130) ((131 . 162) 184 . 194) (224 . 226) (153 . 161) 167 . 172)
      ((((176 . 177) 179 . 209) (216 . 217) 227 . 229)
       ((230 129 . 132) (133 . 134) 136 . 146) ((154 . 156) 160 . 163) (164 . 169) 170 . 173)
      ((((178 . 181) 185 . 186) (187 . 189) 190 . 196)
       ((198 . 228) 232 . 233) ((1 . 135) 137 . 138) (139 . 140) 141 . 143)
      ((((147 . 149) 150 . 151) (152 . 155) 157 . 158)
       ((165 . 166) 168 . 174) (175 . 180) 182 . 183)
      (((188 . 191) 197 . 231) (239 9 . 142) (144 . 145) 148 . 159)
      (((171 . 206) 215 . 225) (236 . 237) (199 . 207) 234 . 235)
      ((((192 . 193) 200 . 201) (202 . 205) 210 . 213)
       ((218 . 219) 238 . 240) (242 . 243) 255 203 . 204)
      ((((211 . 212) 214 . 221) (222 . 223) 241 . 244)
       ((245 . 246) 247 . 248) (250 . 251) 252 . 253)
      (((254 2 . 3) (4 . 5) 6 . 7) ((8 . 11) 12 . 14) (15 . 16) 17 . 18)
      (((19 . 20) 21 . 23) (24 . 25) 26 . 27) ((28 . 29) 30 . 31)
      (127 . 220) 249 (10 . 13) 22 . 256))


  (define (an-atom? x)
    (and (not (pair? x))
         (not (null? x))))

  (define (huffman-find t s p)
    (if (an-atom? s)
      (cons s (huffman-find t t p))
      (if (null? p)
        '()
        (if (zero? (car p))
          (huffman-find t (car s) (cdr p))
          (huffman-find t (cdr s) (cdr p))))))

  (define (bytes->bits ls) ; ugly
    (define (byte->bits b #!optional (n 8))
      (if (eq? n 0)
        '()
        (cons (modulo b 2) (byte->bits (quotient b 2) (sub1 n)))))
    (reverse (apply append (map byte->bits (reverse ls)))))

  (define (huffman-decode bytes)
    (huffman-find huffman-tree
                  huffman-tree
                  (bytes->bits bytes)))

  ; Naive implementation of Huffman encoding

  (define (bits->bytes bits)
    (if (null? bits)
      '()
      (cons (fold (lambda (x s) (+ (* s 2) x)) 0 (take bits 8))
            (bits->bytes (drop bits 8)))))

  (define (huffman-encode bytes)
    (let* ((bits (append-map (lambda (b) (list-ref huffman-code b)) bytes))
           (r (remainder (length bits) 8))
           (eos (list-ref huffman-code 256))
           (pad (if (zero? r) '() (take eos (- 8 r))))
           (bits (append bits pad)))
      (bits->bytes bits)))

  ;; Section 3.3.1 Static Table (entries defined in Appendix B)

  (define static-table
    '((:authority)
      (:method . "GET")
      (:method . "POST")
      (:path . "/")
      (:path . "/index.html")
      (:scheme . "http")
      (:scheme . "https")
      (:status . "200")
      (:status . "204")
      (:status . "206")
      (:status . "304")
      (:status . "400")
      (:status . "404")
      (:status . "500")
      (accept-charset . "")
      (accept-encoding . "gzip, deflate")
      (accept-language . "")
      (accept-ranges . "")
      (accept . "")
      (access-control-allow-origin . "")
      (age . "")
      (allow . "")
      (authorization . "")
      (cache-control . "")
      (content-disposition . "")
      (content-encoding . "")
      (content-language . "")
      (content-length . "")
      (content-location . "")
      (content-range . "")
      (content-type . "")
      (cookie . "")
      (date . "")
      (etag . "")
      (expect . "")
      (expires . "")
      (from . "")
      (host . "")
      (if-match . "")
      (if-modified-since . "")
      (if-none-match . "")
      (if-range . "")
      (if-unmodified-since . "")
      (last-modified . "")
      (link . "")
      (location . "")
      (max-forwards . "")
      (proxy-authenticate . "")
      (proxy-authorization . "")
      (range . "")
      (referer . "")
      (refresh . "")
      (retry-after . "")
      (server . "")
      (set-cookie . "")
      (strict-transport-security . "")
      (transfer-encoding . "")
      (user-agent . "")
      (vary . "")
      (via . "")
      (www-authenticate . "")))

  (define static-table-length 61)

  ;; Section 3.3.2 Header Table

  (defstruct header-table
    (headers '())
    (usage 0)
    (size SETTINGS-HEADER-TABLE-SIZE))

  ;; Section 3.3.3 Index Address Space
  ;; Note: static-table and header-table indexes start at 1

  (define (index-table-lookup index ht)
    (let ((headers (header-table-headers ht)))
      (if (> index (+ static-table-length (length headers)))
        (make-error)
        (if (<= index static-table-length)
          (list-ref static-table (- index 1))
          (list-ref headers (- index static-table-length 1))))))

  ; Section 5 - Header Table Management

  (define (header-size h)
    (let ((name (car h))
          (value (cdr h)))
      (+ (string-length (symbol->string name))
         (string-length value))))

  (define (header-table-prune ht)
    (let ((usage (header-table-usage ht))
          (size (header-table-size ht))
          (headers (header-table-headers ht)))
      (if (or (zero? usage)
              (null? headers)
              (<= usage size))
        ht
        (header-table-prune
          (update-header-table ht
                               headers: (drop-right headers 1)
                               usage: (- usage (header-size (last headers))))))))

  (define (header-table-change-size ht new-size)
    (header-table-prune
      (update-header-table ht size: new-size)))

  (define (header-table-insert ht entry)
    (let* ((headers (header-table-headers ht))
           (usage (header-table-usage ht))
           (size (header-table-size ht))
           (entry-size (header-size entry))
           (new-headers (cons entry headers)))
      (header-table-prune
        (update-header-table ht
                             headers: new-headers
                             usage: (+ entry-size usage)))))
  (define (header-eq? h)
    (lambda (x) (and (eq? (car x) (car h))
                     (not (null? (cdr x)))
                     (string=? (cdr x) (cdr h)))))

  (define (name-eq? h)
    (lambda (x) (and (eq? (car x) (car h)))))

  (define (header-table-finder pred)
    (lambda (ht h)
      (let* ((hdrs (header-table-headers ht))
             (pred (pred h))
             (in-static? (list-index pred static-table)))
        (or (and in-static?
                 (+ in-static? 1))
            (let ((in-header-table?  (list-index pred hdrs)))
              (and in-header-table?
                   (+ in-header-table? 1 static-table-length)))))))

  (define header-table-find (header-table-finder header-eq?))
  (define header-table-find-name (header-table-finder name-eq?))

  ; HPACK decoder and encoder.
  ; Usage note: An encoder and decoder each maintain a seperate header table as context.
  ; Each HTTP/2 connection should have exactly one encoder and one decoder associated with it.

  ; The decoder is implemented as a simple recursive decent parser

  ; Section 6.1 Integer Representation
  ; instead of prefix we use 2^prefix as argument mask
  ; so prefix 7 is "mask 128"

  (define (rest-of-integer r m ls)
    (or (and (null? ls)
             make-error)
        (let ((o (car ls)))
          (if (< o 128)
            (values (+ r (* m o)) (cdr ls))
            (rest-of-integer (+ r (* m (- o 128)))
                             (* m 128)
                             (cdr ls))))))

  (define (integer mask ls)
    (or (and (null? ls)
             make-error)
        (let ((n (modulo (car ls) mask)))
          (if (eq? (+ n 1) mask)
            (rest-of-integer n 1 (cdr ls))
            (values n (cdr ls))))))

  ; Section 6.2 String Representation

  (define (string-value n ls)
    (or (and (< (length ls) n)
             make-error)
        (values (take ls n) (drop ls n))))

  (define (string-literal ls)
    (or (and (null? ls)
             make-error)
        (let* ((tmp ls)
               (o (car ls))
               (huff (>= o 128)))
          (receive (n ls) (integer 128 ls)
            (receive (s ls) (string-value n ls)
              (values (list->string
                        (map integer->char
                             (if huff (huffman-decode s) s)))
                      ls))))))

  ; Section 7.1 Index Header Field Representation
  ; Simply get an integer with 7-prefix and lookup in index table

  (define (index-header ht ls)
    (receive (n ls)
      (integer 128 ls)
      (values (index-table-lookup n ht)
              ht
              ls)))

  ; Section 7.2 Literal Header Field Representation

  (define (indexed-name ht ls)
    (let* ((o (car ls))
           (m (cond ((> o 64) 64)
                    (else 16))))
      (receive (n ls)
        (integer m ls)
        (let ((name (car (index-table-lookup n ht))))
          (values name ls)))))

  (define (new-name ht ls)
    (receive (s ls)
      (string-literal ls)
      (values (string->symbol s) ls)))

  (define (literal-header-name ht ls)
    (let ((new-name? (member (car ls) '(64 16 0))))
      (if new-name?
        (new-name ht (cdr ls))
        (indexed-name ht ls))))

  (define literal-header-value
    string-literal)

  (define (literal-header ht ls)
    (let ((index? (>= (car ls) 64)))
      (receive (name ls)
        (literal-header-name ht ls)
        (receive (value ls)
          (literal-header-value ls)
          (let* ((h (cons name value))
                 (ht (if index?
                       (header-table-insert ht h)
                       ht)))
            (values h ht ls))))))

  (define (header ht ls)
    (let ((indexed? (> (car ls) 128)))
      (if indexed?
        (index-header ht ls)
        (literal-header ht ls))))

  (define (update-header-table-size ht ls)
    (receive (n ls)
      (integer 32 ls)
      (values (header-table-change-size ht n) ls)))

  (define (header-list headers ht ls)
    (if (null? ls)
      (values headers ht ls)
      (let ((update? (and (< (car ls) 64) (>= (car ls) 32))))
        (if update?
          (receive (ht ls) ; update header table size
            (update-header-table-size ht ls)
            (header-list headers ht ls))
          (receive (h ht ls) ; get a header
            (header ht ls)
            (header-list (cons h headers) ht ls))))))

  (define (make-hpack-decoder)
    (let ((header-table (make-header-table)))
      (lambda (code)
        (let ((block (map char->integer (string->list code))))
          (receive (headers ht ls)
            (header-list '() header-table block)
            (set! header-table ht)
            (reverse headers))))))

  ;; Encoder

  (define (rest-of-integer->code n)
    (if (< n 128)
      (list n)
      (cons (+ 128 (modulo n 128)) (rest-of-integer->code (quotient n 128)))))

  (define (integer->code base mask n)
    (if (> n mask)
      (cons (+ base mask)
            (rest-of-integer->code (- n mask)))
      (list (+ base n))))

  (define (string->code s)
    (let* ((bytes (map char->integer (string->list s)))
           (h (huffman-encode bytes))
           (huffman? (< (length h) (length bytes)))
           (len (min (length h) (length bytes)))
           (to-send (if huffman?  h bytes))
           (m (if huffman? 128 0)))
      (append
        (integer->code m 127 len)
        to-send)))

  (define (header->code h index name-index index-header?)
    (if index
      (integer->code 128 127 index)
      (if name-index
        (append (if index-header?
                  (integer->code 64 63 name-index)
                  (integer->code 16 15 name-index))
                (string->code (cdr h)))
        (append (list (if index-header? 64 16))
                (string->code (symbol->string (car h)))
                (string->code (cdr h))))))

  (define (hpack-encode headers header-table index-header?)
    (if (null? headers)
      '()
      (let* ((h (car headers))
             (index (header-table-find header-table h))
             (name-index (header-table-find-name header-table h))
             (code (header->code h index name-index index-header?))
             (header-table (if (and index-header? (not index))
                             (header-table-insert header-table h)
                             header-table)))
        (cons code (hpack-encode (cdr headers) header-table index-header?)))))

  (define (make-hpack-encoder)
    (let ((header-table (make-header-table)))
      (lambda (headers #!optional (index-header? #t))
        (list->string
          (map integer->char
               (apply append
                      (hpack-encode headers
                                    header-table
                                    index-header?))))))))

