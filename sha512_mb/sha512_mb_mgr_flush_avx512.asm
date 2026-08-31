;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2011-2016 Intel Corporation All rights reserved.
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

%include "sha512_job.asm"
%include "sha512_mb_mgr_datastruct.asm"
%include "reg_sizes.asm"

extern sha512_mb_x8_avx512

[bits 64]
default rel
section .text

%ifidn __OUTPUT_FORMAT__, elf64
; LINUX register definitions
%define arg1    rdi ; rcx
%define arg2    rsi ; rdx

; idx needs to be other than arg1, arg2, rbx, r12
%define idx     rdx ; rsi
%else
; WINDOWS register definitions
%define arg1    rcx
%define arg2    rdx

; idx needs to be other than arg1, arg2, rbx, r12
%define idx     rsi
%endif

; Common definitions
%define state   arg1
%define job     arg2
%define len2    arg2

%define num_lanes_inuse r9
%define unused_lanes    rbx
%define lane_data       rbx
%define tmp2            rbx

%define job_rax         rax
%define tmp1            rax
%define size_offset     rax
%define tmp             rax
%define start_offset    rax

%define tmp3            arg1

%define extra_blocks    arg2
%define p               arg2

%define tmp4            r8
%define lens0           r8

%define num_lanes_inuse r9
%define lens1           r9
%define lens2           r10
%define lens3           r11

struc stack_frame
	.xmm: resb 16*10
	.gpr: resb 8*8
	.rsp: resb 8
endstruc

; STACK_SPACE needs to be an odd multiple of 8
%define _XMM_SAVE       stack_frame.xmm
%define _GPR_SAVE       stack_frame.gpr
%define STACK_SPACE     stack_frame_size

%define APPEND(a,b) a %+ b

; ISAL_SHA512_JOB* _sha512_mb_mgr_flush_avx512(ISAL_SHA512_MB_JOB_MGR *state)
; arg 1 : rcx : state
mk_global _sha512_mb_mgr_flush_avx512, function, internal
_sha512_mb_mgr_flush_avx512:
	endbranch

%ifidn __OUTPUT_FORMAT__, win64
	mov     rax, rsp

	sub     rsp, STACK_SPACE

	mov     [rsp + stack_frame.rsp], rax

	mov     [rsp + _GPR_SAVE + 8*0], rbx
	mov     [rsp + _GPR_SAVE + 8*3], rbp
	mov     [rsp + _GPR_SAVE + 8*4], r12
	mov     [rsp + _GPR_SAVE + 8*5], r13
	mov     [rsp + _GPR_SAVE + 8*6], r14
	mov     [rsp + _GPR_SAVE + 8*7], r15
	mov     [rsp + _GPR_SAVE + 8*1], rsi
	mov     [rsp + _GPR_SAVE + 8*2], rdi
	vmovdqu  [rsp + _XMM_SAVE + 16*0], xmm6
	vmovdqu  [rsp + _XMM_SAVE + 16*1], xmm7
	vmovdqu  [rsp + _XMM_SAVE + 16*2], xmm8
	vmovdqu  [rsp + _XMM_SAVE + 16*3], xmm9
	vmovdqu  [rsp + _XMM_SAVE + 16*4], xmm10
	vmovdqu  [rsp + _XMM_SAVE + 16*5], xmm11
	vmovdqu  [rsp + _XMM_SAVE + 16*6], xmm12
	vmovdqu  [rsp + _XMM_SAVE + 16*7], xmm13
	vmovdqu  [rsp + _XMM_SAVE + 16*8], xmm14
	vmovdqu  [rsp + _XMM_SAVE + 16*9], xmm15
%endif
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15

	mov	DWORD(num_lanes_inuse), [state + _num_lanes_inuse]
	xor	rax, rax, ; if lines_inuse = 0 then exit and return 0. Longer opcode for alignment
	test	DWORD(num_lanes_inuse), DWORD(num_lanes_inuse)
	jz	return

	; find a lane with a non-null job
	vpxor	xmm0, xmm0, xmm0
	vpcmpneqq k1, zmm0, [state + _ldata +  _job_in_lane]
	kmovb   DWORD(idx), k1
	tzcnt	DWORD(idx), DWORD(idx)

	; copy idx to empty lanes
copy_lane_data:
	lea             rax, [state + _args + _data_ptr]
	knotb		k1, k1	; k1 now select the null jobs
        vpternlogq      zmm3, zmm3, zmm3, 0xFF ; 0xFFFF mask
        vpbroadcastq    zmm1, [rax + 8*idx]
        vmovdqu64       [rax]{k1}, zmm1
        vmovdqu64       zmm0, [state + _lens]
        vpsllq          zmm3, zmm3, 32
        vporq           zmm0{k1}, zmm3

	; Find min length, len in sha512_mgr is 64bit, high 32bit is block num, low 8bit is idx
	vextracti64x4 ymm1, zmm0, 0x1
	vpminuq ymm2, ymm0, ymm1	; ymm2 has {D,i,C,i,B,i,A,i}
	vpalignr ymm4, ymm3, ymm2, 8	; ymm4 has {x,i,D,i,x,i,B,i}
	vpminuq ymm2, ymm2, ymm4	; ymm2 has {x,i,F,i,x,i,E,i}
	vextracti128 xmm4, ymm2, 1	; ymm4 has {x,i,x,i,x,i,F,i}
	vpminuq xmm2, xmm2, xmm4	; ymm2 has min value in high dword

	vmovq   idx, xmm2
	mov     len2, idx
	shr     len2, 32		; SHA512 blocksize is 1024bit
	and     DWORD(idx), 0xF
	test	DWORD(len2), DWORD(len2)
	jz      len_is_0

; mgr len element 0xnnnnnnnn 0000000m, nnnnnnnn is blocknum, m is index
	vpand   xmm2, xmm2, xmm3	; {E,0}
	vpbroadcastq zmm2, xmm2	; ymm2 has {E,0,E,0,E,0,E,0}

	vpsubd  zmm0, zmm0, zmm2

	vmovdqu8 [state + _lens], zmm0

	; "state" and "args" are the same address, arg1
	; len is arg2
	call    sha512_mb_x8_avx512
	; state and idx are intact

len_is_0:
	; process completed job "idx"
        vpmovzxwq zmm1, [rel gather] ; gather indexes
	lea     lane_data, [state + _ldata + idx*8]
	xor	len2%+d, len2%+d
	mov     job_rax, [lane_data + _job_in_lane]
	mov     qword [lane_data + _job_in_lane], len2 ; 0
	add	len2%+d, ISAL_STS_COMPLETED
	mov     dword [job_rax + _status], len2%+d
	mov     unused_lanes, [state + _unused_lanes]
	shl     unused_lanes, 8
	or      unused_lanes, idx
	mov     [state + _unused_lanes], unused_lanes

	dec	[state + _num_lanes_inuse]
	lea	state, [state + _args_digest + 8*idx]
	kxnorw	k1, k1, k1
	vpgatherqq zmm0{k1}, [state+zmm1]; gather results
	vmovdqa64  [job_rax + _result_digest], zmm0

return:

%ifidn __OUTPUT_FORMAT__, win64
	vmovdqu  xmm6,  [rsp + _XMM_SAVE + 16*0]
	vmovdqu  xmm7,  [rsp + _XMM_SAVE + 16*1]
	vmovdqu  xmm8,  [rsp + _XMM_SAVE + 16*2]
	vmovdqu  xmm9,  [rsp + _XMM_SAVE + 16*3]
	vmovdqu  xmm10, [rsp + _XMM_SAVE + 16*4]
	vmovdqu  xmm11, [rsp + _XMM_SAVE + 16*5]
	vmovdqu  xmm12, [rsp + _XMM_SAVE + 16*6]
	vmovdqu  xmm13, [rsp + _XMM_SAVE + 16*7]
	vmovdqu  xmm14, [rsp + _XMM_SAVE + 16*8]
	vmovdqu  xmm15, [rsp + _XMM_SAVE + 16*9]
	mov     rsi, [rsp + _GPR_SAVE + 8*1]
	mov     rdi, [rsp + _GPR_SAVE + 8*2]
	mov     rbx, [rsp + _GPR_SAVE + 8*0]
	mov     rbp, [rsp + _GPR_SAVE + 8*3]
	mov     r12, [rsp + _GPR_SAVE + 8*4]
	mov     r13, [rsp + _GPR_SAVE + 8*5]
	mov     r14, [rsp + _GPR_SAVE + 8*6]
	mov     r15, [rsp + _GPR_SAVE + 8*7]

	mov	rsp, [rsp + stack_frame.rsp]
%endif
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbp
	pop rbx

	ret

section .rodata
align 16
gather: dw 64*0
        dw 64*1
        dw 64*2
        dw 64*3
        dw 64*4
        dw 64*5
        dw 64*6
        dw 64*7
