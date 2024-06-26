;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2011-2020 Intel Corporation All rights reserved.
;
;  Redistribution and use in source and binary forms, with or without
;  modification, are permitted provided that the following conditions
;  are met:
;    * Redistributions of source code must retain the above copyright
;      notice, this list of conditions and the following disclaimer.
;    * Redistributions in binary form must reproduce the above copyright
;      notice, this list of conditions and the following disclaimer in
;      the documentation and/or other materials provided with the
;      distribution.
;    * Neither the name of Intel Corporation nor the names of its
;      contributors may be used to endorse or promote products derived
;      from this software without specific prior written permission.
;
;  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
;  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
;  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
;  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
;  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
;  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
;  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
;  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%include "reg_sizes.asm"
%include "multibinary.asm"
default rel
[bits 64]

extern _sm3_ctx_mgr_init_base
extern _sm3_ctx_mgr_submit_base
extern _sm3_ctx_mgr_flush_base

extern _sm3_ctx_mgr_init_avx2
extern _sm3_ctx_mgr_submit_avx2
extern _sm3_ctx_mgr_flush_avx2

%ifdef HAVE_AS_KNOWS_AVX512
 extern _sm3_ctx_mgr_init_avx512
 extern _sm3_ctx_mgr_submit_avx512
 extern _sm3_ctx_mgr_flush_avx512
%endif

;;; *_mbinit are initial values for *_dispatched; is updated on first call.
;;; Therefore, *_dispatch_init is only executed on first call.

; Initialise symbols
mbin_interface _sm3_ctx_mgr_init
mbin_interface _sm3_ctx_mgr_submit
mbin_interface _sm3_ctx_mgr_flush

;; have not implement see/avx yet
%ifdef HAVE_AS_KNOWS_AVX512
  mbin_dispatch_init6 _sm3_ctx_mgr_init, _sm3_ctx_mgr_init_base, \
	_sm3_ctx_mgr_init_base, _sm3_ctx_mgr_init_base, _sm3_ctx_mgr_init_avx2, \
	_sm3_ctx_mgr_init_avx512
  mbin_dispatch_init6 _sm3_ctx_mgr_submit, _sm3_ctx_mgr_submit_base, \
	_sm3_ctx_mgr_submit_base, _sm3_ctx_mgr_submit_base, _sm3_ctx_mgr_submit_avx2, \
	_sm3_ctx_mgr_submit_avx512
  mbin_dispatch_init6 _sm3_ctx_mgr_flush, _sm3_ctx_mgr_flush_base, \
	_sm3_ctx_mgr_flush_base, _sm3_ctx_mgr_flush_base, _sm3_ctx_mgr_flush_avx2, \
	_sm3_ctx_mgr_flush_avx512
%else
  mbin_dispatch_init _sm3_ctx_mgr_init, _sm3_ctx_mgr_init_base, \
	_sm3_ctx_mgr_init_base, _sm3_ctx_mgr_init_avx2
  mbin_dispatch_init _sm3_ctx_mgr_submit, _sm3_ctx_mgr_submit_base, \
	_sm3_ctx_mgr_submit_base,_sm3_ctx_mgr_submit_avx2
  mbin_dispatch_init _sm3_ctx_mgr_flush, _sm3_ctx_mgr_flush_base, \
	_sm3_ctx_mgr_flush_base,_sm3_ctx_mgr_flush_avx2
%endif

;;;       func  			core, ver, snum
slversion _sm3_ctx_mgr_init,  	00,   00, 2300
slversion _sm3_ctx_mgr_submit,	00,   00, 2301
slversion _sm3_ctx_mgr_flush, 	00,   00, 2302

