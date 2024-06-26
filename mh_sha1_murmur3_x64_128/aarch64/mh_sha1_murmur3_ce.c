/**********************************************************************
  Copyright(c) 2021 Arm Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Arm Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/

#include <string.h>
#include "mh_sha1_murmur3_aarch64_internal.h"

extern void
mh_sha1_tail_ce(uint8_t *partial_buffer, uint32_t total_len,
                uint32_t (*mh_sha1_segs_digests)[ISAL_HASH_SEGS], uint8_t *frame_buffer,
                uint32_t mh_sha1_digest[ISAL_SHA1_DIGEST_WORDS]);

extern void
mh_sha1_block_ce(const uint8_t *input_data,
                 uint32_t digests[ISAL_SHA1_DIGEST_WORDS][ISAL_HASH_SEGS],
                 uint8_t frame_buffer[ISAL_MH_SHA1_BLOCK_SIZE], uint32_t num_blocks);

// mh_sha1_murmur3_update_ce.c
#define UPDATE_FUNCTION mh_sha1_murmur3_update_ce
#define BLOCK_FUNCTION  mh_sha1_murmur3_block_ce
#include "mh_sha1_murmur3_x64_128_update_base.c"
#undef UPDATE_FUNCTION
#undef BLOCK_FUNCTION

// mh_sha1_murmur3_finalize_ce.c
#define FINALIZE_FUNCTION     mh_sha1_murmur3_finalize_ce
#define MH_SHA1_TAIL_FUNCTION mh_sha1_tail_ce
#include "mh_sha1_murmur3_x64_128_finalize_base.c"
#undef FINALIZE_FUNCTION
#undef MH_SHA1_TAIL_FUNCTION
