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

;; code to compute 16 SHA1 using AVX
;;

%include "reg_sizes.asm"

[bits 64]
default rel
section .text

;; Magic functions defined in FIPS 180-1
;;
; macro MAGIC_F0 F,B,C,D,T   ;; F = (D ^ (B & (C ^ D)))
%macro MAGIC_F0 5
%define %%regF %1
%define %%regB %2
%define %%regC %3
%define %%regD %4
%define %%regT %5
    vpxor  %%regF, %%regC,%%regD
    vpand  %%regF, %%regF,%%regB
    vpxor  %%regF, %%regF,%%regD
%endmacro

; macro MAGIC_F1 F,B,C,D,T   ;; F = (B ^ C ^ D)
%macro MAGIC_F1 5
%define %%regF %1
%define %%regB %2
%define %%regC %3
%define %%regD %4
%define %%regT %5
    vpxor  %%regF,%%regD,%%regC
    vpxor  %%regF,%%regF,%%regB
%endmacro

; macro MAGIC_F2 F,B,C,D,T   ;; F = ((B & C) | (B & D) | (C & D))
%macro MAGIC_F2 5
%define %%regF %1
%define %%regB %2
%define %%regC %3
%define %%regD %4
%define %%regT %5
    vpor   %%regF,%%regB,%%regC
    vpand  %%regT,%%regB,%%regC
    vpand  %%regF,%%regF,%%regD
    vpor   %%regF,%%regF,%%regT
%endmacro

; macro MAGIC_F3 F,B,C,D,T   ;; F = (B ^ C ^ D)
%macro MAGIC_F3 5
%define %%regF %1
%define %%regB %2
%define %%regC %3
%define %%regD %4
%define %%regT %5
    MAGIC_F1 %%regF,%%regB,%%regC,%%regD,%%regT
%endmacro

; PROLD reg, imm, tmp
%macro PROLD 3
%define %%reg %1
%define %%imm %2
%define %%tmp %3
	vpsrld  %%tmp, %%reg, (32-(%%imm))
	vpslld  %%reg, %%reg, %%imm
	vpor    %%reg, %%reg, %%tmp
%endmacro

; non-destructive
; PROLD_nd reg, imm, tmp, src
%macro PROLD_nd 4
%define %%reg %1
%define %%imm %2
%define %%tmp %3
%define %%src %4
	vpsrld  %%tmp, %%src, (32-(%%imm))
	vpslld  %%reg, %%src, %%imm
	vpor    %%reg, %%reg, %%tmp
%endmacro

%macro SHA1_STEP_00_15 11
%define %%regA  %1
%define %%regB  %2
%define %%regC  %3
%define %%regD  %4
%define %%regE  %5
%define %%regT  %6
%define %%regF  %7
%define %%memW  %8
%define %%immCNT %9
%define %%MAGIC %10
%define %%data %11
	vpaddd  %%regE, %%regE,%%immCNT
	vpaddd  %%regE, %%regE,[%%data + (%%memW * 16)]
	PROLD_nd        %%regT,5, %%regF,%%regA
	vpaddd  %%regE, %%regE,%%regT
	%%MAGIC %%regF,%%regB,%%regC,%%regD,%%regT      ;; FUN  = MAGIC_Fi(B,C,D)
	PROLD   %%regB,30, %%regT
	vpaddd  %%regE, %%regE,%%regF
%endmacro
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SHA1_STEP_16_79 11
%define %%regA  %1
%define %%regB  %2
%define %%regC  %3
%define %%regD  %4
%define %%regE  %5
%define %%regT  %6
%define %%regF  %7
%define %%memW  %8
%define %%immCNT %9
%define %%MAGIC %10
%define %%data %11
	vpaddd  %%regE, %%regE,%%immCNT

	vmovdqa W14, [%%data + ((%%memW - 14) & 15) * 16]
	vpxor   W16, W16, W14
	vpxor   W16, W16, [%%data + ((%%memW -  8) & 15) * 16]
	vpxor   W16, W16, [%%data + ((%%memW -  3) & 15) * 16]

	vpsrld  %%regF, W16, (32-1)
	vpslld  W16, W16, 1
	vpor    %%regF, %%regF, W16
	ROTATE_W

	vmovdqa [%%data + ((%%memW - 0) & 15) * 16],%%regF
	vpaddd  %%regE, %%regE,%%regF

	PROLD_nd        %%regT,5, %%regF, %%regA
	vpaddd  %%regE, %%regE,%%regT
	%%MAGIC %%regF,%%regB,%%regC,%%regD,%%regT      ;; FUN  = MAGIC_Fi(B,C,D)
	PROLD   %%regB,30, %%regT
	vpaddd  %%regE,%%regE,%%regF
%endmacro

;; Insert murmur's instructions into this macro.
;; Every section_loop of mh_sha1 calls SHA1_STEP_16_79 64 times and processes 256Byte.
;; So insert 1 murmur block into every 4 SHA1_STEP_16_79.
%define SHA1_STEP_16_79(J) SHA1_STEP_16_79_ %+ J

%macro SHA1_STEP_16_79_0 11
%define %%regA  %1
%define %%regB  %2
%define %%regC  %3
%define %%regD  %4
%define %%regE  %5
%define %%regT  %6
%define %%regF  %7
%define %%memW  %8
%define %%immCNT %9
%define %%MAGIC %10
%define %%data %11
	vpaddd  %%regE, %%regE,%%immCNT

	vmovdqa W14, [%%data + ((%%memW - 14) & 15) * 16]
	vpxor   W16, W16, W14
	vpxor   W16, W16, [%%data + ((%%memW -  8) & 15) * 16]
	vpxor   W16, W16, [%%data + ((%%memW -  3) & 15) * 16]

	vpsrld  %%regF, W16, (32-1)
	mov	mur_data1, [mur_in_p]
	mov	mur_data2, [mur_in_p + 8]
	vpslld  W16, W16, 1
	vpor    %%regF, %%regF, W16
	ROTATE_W

	vmovdqa [%%data + ((%%memW - 0) & 15) * 16],%%regF
	imul	mur_data1, mur_c1_r
	vpaddd  %%regE, %%regE,%%regF

	PROLD_nd        %%regT,5, %%regF, %%regA
	vpaddd  %%regE, %%regE,%%regT
	%%MAGIC %%regF,%%regB,%%regC,%%regD,%%regT      ;; FUN  = MAGIC_Fi(B,C,D)
	imul	mur_data2, mur_c2_r
	PROLD   %%regB,30, %%regT
	vpaddd  %%regE,%%regE,%%regF
%endmacro

%macro SHA1_STEP_16_79_1 11
%define %%regA  %1
%define %%regB  %2
%define %%regC  %3
%define %%regD  %4
%define %%regE  %5
%define %%regT  %6
%define %%regF  %7
%define %%memW  %8
%define %%immCNT %9
%define %%MAGIC %10
%define %%data %11
	vpaddd  %%regE, %%regE,%%immCNT
	rol	mur_data1, R1
	vmovdqa W14, [%%data + ((%%memW - 14) & 15) * 16]
	vpxor   W16, W16, W14
	vpxor   W16, W16, [%%data + ((%%memW -  8) & 15) * 16]
	vpxor   W16, W16, [%%data + ((%%memW -  3) & 15) * 16]

	vpsrld  %%regF, W16, (32-1)
	vpslld  W16, W16, 1
	rol	mur_data2, R2
	vpor    %%regF, %%regF, W16
	ROTATE_W

	vmovdqa [%%data + ((%%memW - 0) & 15) * 16],%%regF
	imul	mur_data1, mur_c2_r
	vpaddd  %%regE, %%regE,%%regF

	PROLD_nd        %%regT,5, %%regF, %%regA
	vpaddd  %%regE, %%regE,%%regT
	%%MAGIC %%regF,%%regB,%%regC,%%regD,%%regT      ;; FUN  = MAGIC_Fi(B,C,D)
	imul	mur_data2, mur_c1_r
	PROLD   %%regB,30, %%regT
	add	mur_in_p, 16
	vpaddd  %%regE,%%regE,%%regF
%endmacro

%macro SHA1_STEP_16_79_2 11
%define %%regA  %1
%define %%regB  %2
%define %%regC  %3
%define %%regD  %4
%define %%regE  %5
%define %%regT  %6
%define %%regF  %7
%define %%memW  %8
%define %%immCNT %9
%define %%MAGIC %10
%define %%data %11
	vpaddd  %%regE, %%regE,%%immCNT

	vmovdqa W14, [%%data + ((%%memW - 14) & 15) * 16]
	xor	mur_hash1, mur_data1
	vpxor   W16, W16, W14
	vpxor   W16, W16, [%%data + ((%%memW -  8) & 15) * 16]
	vpxor   W16, W16, [%%data + ((%%memW -  3) & 15) * 16]
	rol	mur_hash1, R3
	vpsrld  %%regF, W16, (32-1)
	vpslld  W16, W16, 1
	vpor    %%regF, %%regF, W16
	ROTATE_W

	vmovdqa [%%data + ((%%memW - 0) & 15) * 16],%%regF
	add	mur_hash1, mur_hash2
	vpaddd  %%regE, %%regE,%%regF

	PROLD_nd        %%regT,5, %%regF, %%regA
	lea	mur_hash1, [mur_hash1 + mur_hash1*4 + N1]
	vpaddd  %%regE, %%regE,%%regT
	%%MAGIC %%regF,%%regB,%%regC,%%regD,%%regT      ;; FUN  = MAGIC_Fi(B,C,D)
	PROLD   %%regB,30, %%regT
	vpaddd  %%regE,%%regE,%%regF
%endmacro

%macro SHA1_STEP_16_79_3 11
%define %%regA  %1
%define %%regB  %2
%define %%regC  %3
%define %%regD  %4
%define %%regE  %5
%define %%regT  %6
%define %%regF  %7
%define %%memW  %8
%define %%immCNT %9
%define %%MAGIC %10
%define %%data %11
	vpaddd  %%regE, %%regE,%%immCNT

	vmovdqa W14, [%%data + ((%%memW - 14) & 15) * 16]
	xor	mur_hash2, mur_data2
	vpxor   W16, W16, W14
	vpxor   W16, W16, [%%data + ((%%memW -  8) & 15) * 16]
	vpxor   W16, W16, [%%data + ((%%memW -  3) & 15) * 16]
	rol	mur_hash2, R4
	vpsrld  %%regF, W16, (32-1)
	vpslld  W16, W16, 1
	vpor    %%regF, %%regF, W16
	ROTATE_W

	vmovdqa [%%data + ((%%memW - 0) & 15) * 16],%%regF
	add	mur_hash2, mur_hash1
	vpaddd  %%regE, %%regE,%%regF

	PROLD_nd        %%regT,5, %%regF, %%regA
	vpaddd  %%regE, %%regE,%%regT
	%%MAGIC %%regF,%%regB,%%regC,%%regD,%%regT      ;; FUN  = MAGIC_Fi(B,C,D)
	PROLD   %%regB,30, %%regT
	lea	mur_hash2, [mur_hash2 + mur_hash2*4 + N2]
	vpaddd  %%regE,%%regE,%%regF
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%ifidn __OUTPUT_FORMAT__, elf64
 ; Linux
 %define arg0  rdi
 %define arg1  rsi
 %define arg2  rdx
 %define arg3  rcx

 %define arg4  r8d
 %define arg5  r9

 %define tmp1  r10
 %define tmp2  r11
 %define tmp3  r12		; must be saved and restored
 %define tmp4  r13		; must be saved and restored
 %define tmp5  r14		; must be saved and restored
 %define tmp6  r15		; must be saved and restored
 %define tmp7  rbx		; must be saved and restored
 %define tmp8  rbp		; must be saved and restored
 %define return rax

 %define func(x) x:
 %macro FUNC_SAVE 0
	push	r12
	push	r13
	push	r14
	push	r15
	push	rbx
	push	rbp
 %endmacro
 %macro FUNC_RESTORE 0
	pop	rbp
	pop	rbx
	pop	r15
	pop	r14
	pop	r13
	pop	r12
 %endmacro
%else
 ; Windows
 %define arg0   rcx
 %define arg1   rdx
 %define arg2   r8
 %define arg3   r9

 %define arg4   r10d
 %define arg5   r11
 %define tmp1   r12		; must be saved and restored
 %define tmp2   r13		; must be saved and restored
 %define tmp3   r14		; must be saved and restored
 %define tmp4   r15		; must be saved and restored
 %define tmp5   rdi		; must be saved and restored
 %define tmp6   rsi		; must be saved and restored
 %define tmp7   rbx		; must be saved and restored
 %define tmp8   rbp		; must be saved and restored
 %define return rax

 %define stack_size  10*16 + 9*8		; must be an odd multiple of 8
 %define PS 8
 %define arg(x)      [rsp + stack_size + PS + PS*x]
 %define func(x) proc_frame x
 %macro FUNC_SAVE 0
	alloc_stack	stack_size
	save_xmm128	xmm6, 0*16
	save_xmm128	xmm7, 1*16
	save_xmm128	xmm8, 2*16
	save_xmm128	xmm9, 3*16
	save_xmm128	xmm10, 4*16
	save_xmm128	xmm11, 5*16
	save_xmm128	xmm12, 6*16
	save_xmm128	xmm13, 7*16
	save_xmm128	xmm14, 8*16
	save_xmm128	xmm15, 9*16
	save_reg	r12,  10*16 + 0*8
	save_reg	r13,  10*16 + 1*8
	save_reg	r14,  10*16 + 2*8
	save_reg	r15,  10*16 + 3*8
	save_reg	rdi,  10*16 + 4*8
	save_reg	rsi,  10*16 + 5*8
	save_reg	rbx,  10*16 + 6*8
	save_reg	rbp,  10*16 + 7*8
	end_prolog
	mov	arg4, arg(4)
 %endmacro

 %macro FUNC_RESTORE 0
	movdqa	xmm6, [rsp + 0*16]
	movdqa	xmm7, [rsp + 1*16]
	movdqa	xmm8, [rsp + 2*16]
	movdqa	xmm9, [rsp + 3*16]
	movdqa	xmm10, [rsp + 4*16]
	movdqa	xmm11, [rsp + 5*16]
	movdqa	xmm12, [rsp + 6*16]
	movdqa	xmm13, [rsp + 7*16]
	movdqa	xmm14, [rsp + 8*16]
	movdqa	xmm15, [rsp + 9*16]
	mov	r12,  [rsp + 10*16 + 0*8]
	mov	r13,  [rsp + 10*16 + 1*8]
	mov	r14,  [rsp + 10*16 + 2*8]
	mov	r15,  [rsp + 10*16 + 3*8]
	mov	rdi,  [rsp + 10*16 + 4*8]
	mov	rsi,  [rsp + 10*16 + 5*8]
 	mov	rbx,  [rsp + 10*16 + 6*8]
	mov	rbp,  [rsp + 10*16 + 7*8]
	add	rsp, stack_size
 %endmacro
%endif
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%define loops 		arg4
;variables of mh_sha1
%define mh_in_p  	arg0
%define mh_digests_p 	arg1
%define mh_data_p	arg2
%define mh_segs  	tmp1
;variables of murmur3
%define mur_in_p  	tmp2
%define mur_digest_p 	arg3
%define mur_hash1	 tmp3
%define mur_hash2	 tmp4
%define mur_data1	 tmp5
%define mur_data2	 return
%define mur_c1_r	 tmp6
%define mur_c2_r	 arg5
; constants of murmur3_x64_128
%define R1	31
%define R2	33
%define R3	27
%define R4	31
%define M	5
%define N1	0x52dce729;DWORD
%define N2	0x38495ab5;DWORD
%define C1	QWORD(0x87c37b91114253d5)
%define C2	QWORD(0x4cf5ad432745937f)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;variables used by storing segs_digests on stack
%define RSP_SAVE	tmp7
%define FRAMESZ 	4*5*16		;BYTES*DWORDS*SEGS
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%define VMOVPS  vmovups

%define A       xmm0
%define B       xmm1
%define C       xmm2
%define D       xmm3
%define E       xmm4
%define F       xmm5 ; tmp
%define G       xmm6 ; tmp

%define TMP     G
%define FUN     F
%define K       xmm7

%define AA      xmm8
%define BB      xmm9
%define CC      xmm10
%define DD      xmm11
%define EE      xmm12

%define T0      xmm6
%define T1      xmm7
%define T2      xmm8
%define T3      xmm9
%define T4      xmm10
%define T5      xmm11

%macro ROTATE_ARGS 0
%xdefine TMP_ E
%xdefine E D
%xdefine D C
%xdefine C B
%xdefine B A
%xdefine A TMP_
%endm

%define W14     xmm13
%define W15     xmm14
%define W16     xmm15

%macro ROTATE_W 0
%xdefine TMP_ W16
%xdefine W16 W15
%xdefine W15 W14
%xdefine W14 TMP_
%endm


;init hash digests
; segs_digests:low addr-> high_addr
; a  | b  |  c | ...|  p | (16)
; h0 | h0 | h0 | ...| h0 |    | Aa| Ab | Ac |...| Ap |
; h1 | h1 | h1 | ...| h1 |    | Ba| Bb | Bc |...| Bp |
; ....
; h5 | h5 | h5 | ...| h5 |    | Ea| Eb | Ec |...| Ep |

align 32
;void _mh_sha1_murmur3_x64_128_block_avx (const uint8_t * input_data,
;				uint32_t mh_sha1_digests[ISAL_SHA1_DIGEST_WORDS][ISAL_HASH_SEGS],
;				uint8_t frame_buffer[ISAL_MH_SHA1_BLOCK_SIZE],
;				uint32_t murmur3_x64_128_digests[ISAL_MURMUR3_x64_128_DIGEST_WORDS],
;				uint32_t num_blocks);
; arg 0 pointer to input data
; arg 1 pointer to digests, include segments digests(uint32_t digests[16][5])
; arg 2 pointer to aligned_frame_buffer which is used to save the big_endian data.
; arg 3 pointer to murmur3 digest
; arg 4 number  of 1KB blocks
;
mk_global _mh_sha1_murmur3_x64_128_block_avx, function, internal
func(_mh_sha1_murmur3_x64_128_block_avx)
	endbranch
	FUNC_SAVE
	; save rsp
	mov	RSP_SAVE, rsp

	cmp	loops, 0
	jle	.return

	; leave enough space to store segs_digests
	sub     rsp, FRAMESZ
	; align rsp to 16 Bytes needed by avx
	and	rsp, ~0x0F

 %assign I 0					; copy segs_digests into stack
 %rep 5
	VMOVPS  A, [mh_digests_p + I*64 + 16*0]
	VMOVPS  B, [mh_digests_p + I*64 + 16*1]
	VMOVPS  C, [mh_digests_p + I*64 + 16*2]
	VMOVPS  D, [mh_digests_p + I*64 + 16*3]

	vmovdqa [rsp + I*64 + 16*0], A
	vmovdqa [rsp + I*64 + 16*1], B
	vmovdqa [rsp + I*64 + 16*2], C
	vmovdqa [rsp + I*64 + 16*3], D
 %assign I (I+1)
 %endrep

 	;init murmur variables
	mov	mur_in_p, mh_in_p	;different steps between murmur and mh_sha1
	;load murmur hash digests and multiplier
	mov	mur_hash1, [mur_digest_p]
	mov	mur_hash2, [mur_digest_p + 8]
	mov	mur_c1_r,  C1
	mov	mur_c2_r,  C2

.block_loop:
	;transform to big-endian data and store on aligned_frame
	vmovdqa F, [PSHUFFLE_BYTE_FLIP_MASK]
	;transform input data from DWORD*16_SEGS*5 to DWORD*4_SEGS*5*4
 %assign I 0
 %rep 16
	VMOVPS   T0,[mh_in_p + I*64+0*16]
	VMOVPS   T1,[mh_in_p + I*64+1*16]
	VMOVPS   T2,[mh_in_p + I*64+2*16]
	VMOVPS   T3,[mh_in_p + I*64+3*16]

	vpshufb  T0, F
	vmovdqa  [mh_data_p +(I)*16 +0*256],T0
	vpshufb  T1, F
	vmovdqa  [mh_data_p +(I)*16 +1*256],T1
	vpshufb  T2, F
	vmovdqa  [mh_data_p +(I)*16 +2*256],T2
	vpshufb  T3, F
	vmovdqa  [mh_data_p +(I)*16 +3*256],T3
 %assign I (I+1)
 %endrep

 	mov	mh_segs, 0			;start from the first 4 segments
 .segs_loop:
	;; Initialize digests
	vmovdqa  A, [rsp + 0*64 + mh_segs]
	vmovdqa  B, [rsp + 1*64 + mh_segs]
	vmovdqa  C, [rsp + 2*64 + mh_segs]
	vmovdqa  D, [rsp + 3*64 + mh_segs]
	vmovdqa  E, [rsp + 4*64 + mh_segs]

	vmovdqa  AA, A
	vmovdqa  BB, B
	vmovdqa  CC, C
	vmovdqa  DD, D
	vmovdqa  EE, E
;;
;; perform 0-79 steps
;;
	vmovdqa K, [K00_19]
;; do rounds 0...15
 %assign I 0
 %rep 16
	SHA1_STEP_00_15 A,B,C,D,E, TMP,FUN, I, K, MAGIC_F0, mh_data_p
	ROTATE_ARGS
 %assign I (I+1)
 %endrep

;; do rounds 16...19
	vmovdqa W16, [mh_data_p + ((16 - 16) & 15) * 16]
	vmovdqa W15, [mh_data_p + ((16 - 15) & 15) * 16]
 %rep 4
 %assign J (I % 4)
	SHA1_STEP_16_79(J) A,B,C,D,E, TMP,FUN, I, K, MAGIC_F0, mh_data_p
	ROTATE_ARGS
 %assign I (I+1)
 %endrep

;; do rounds 20...39
	vmovdqa K, [K20_39]
 %rep 20
 %assign J (I % 4)
	SHA1_STEP_16_79(J) A,B,C,D,E, TMP,FUN, I, K, MAGIC_F1, mh_data_p
	ROTATE_ARGS
 %assign I (I+1)
 %endrep

;; do rounds 40...59
	vmovdqa K, [K40_59]
 %rep 20
 %assign J (I % 4)
	SHA1_STEP_16_79(J) A,B,C,D,E, TMP,FUN, I, K, MAGIC_F2, mh_data_p
	ROTATE_ARGS
 %assign I (I+1)
 %endrep

;; do rounds 60...79
	vmovdqa K, [K60_79]
 %rep 20
 %assign J (I % 4)
	SHA1_STEP_16_79(J) A,B,C,D,E, TMP,FUN, I, K, MAGIC_F3, mh_data_p
	ROTATE_ARGS
 %assign I (I+1)
 %endrep

	vpaddd  A, AA
	vpaddd  B, BB
	vpaddd  C, CC
	vpaddd  D, DD
	vpaddd  E, EE

	; write out digests
	vmovdqa  [rsp + 0*64 + mh_segs], A
	vmovdqa  [rsp + 1*64 + mh_segs], B
	vmovdqa  [rsp + 2*64 + mh_segs], C
	vmovdqa  [rsp + 3*64 + mh_segs], D
	vmovdqa  [rsp + 4*64 + mh_segs], E

	add	mh_data_p,	256
	add 	mh_segs, 16
	cmp	mh_segs, 64
	jc 	.segs_loop

	sub	mh_data_p, (1024)
	add 	mh_in_p,   (1024)
	sub     loops, 1
	jne     .block_loop

	;store murmur-hash digest
	mov	[mur_digest_p], mur_hash1
	mov	[mur_digest_p + 8], mur_hash2

 %assign I 0					; copy segs_digests back to mh_digests_p
 %rep 5
	vmovdqa A, [rsp + I*64 + 16*0]
	vmovdqa B, [rsp + I*64 + 16*1]
	vmovdqa C, [rsp + I*64 + 16*2]
	vmovdqa D, [rsp + I*64 + 16*3]

	VMOVPS  [mh_digests_p + I*64 + 16*0], A
	VMOVPS  [mh_digests_p + I*64 + 16*1], B
	VMOVPS  [mh_digests_p + I*64 + 16*2], C
	VMOVPS  [mh_digests_p + I*64 + 16*3], D
 %assign I (I+1)
 %endrep
	mov	rsp, RSP_SAVE			; restore rsp

.return:
	FUNC_RESTORE
	ret

endproc_frame

section .data align=16

align 16
PSHUFFLE_BYTE_FLIP_MASK: dq 0x0405060700010203, 0x0c0d0e0f08090a0b

K00_19:                  dq 0x5A8279995A827999, 0x5A8279995A827999
K20_39:                  dq 0x6ED9EBA16ED9EBA1, 0x6ED9EBA16ED9EBA1
K40_59:                  dq 0x8F1BBCDC8F1BBCDC, 0x8F1BBCDC8F1BBCDC
K60_79:                  dq 0xCA62C1D6CA62C1D6, 0xCA62C1D6CA62C1D6
