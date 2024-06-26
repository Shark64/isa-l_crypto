/**********************************************************************
  Copyright(c) 2011-2016 Intel Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
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

#ifndef UPDATE_FUNCTION
#include "mh_sha1_murmur3_x64_128_internal.h"
#include <string.h>

#define UPDATE_FUNCTION _mh_sha1_murmur3_x64_128_update_base
#define BLOCK_FUNCTION  _mh_sha1_murmur3_x64_128_block_base
#define UPDATE_FUNCTION_SLVER
#endif

int
UPDATE_FUNCTION(struct isal_mh_sha1_murmur3_x64_128_ctx *ctx, const void *buffer, uint32_t len)
{

        uint8_t *partial_block_buffer;
        uint32_t partial_block_len;
        uint32_t num_blocks;
        uint32_t(*mh_sha1_segs_digests)[ISAL_HASH_SEGS];
        uint8_t *aligned_frame_buffer;
        uint32_t *murmur3_x64_128_digest;
        const uint8_t *input_data = (const uint8_t *) buffer;

        if (ctx == NULL)
                return ISAL_MH_SHA1_MURMUR3_CTX_ERROR_NULL;

        if (len == 0)
                return ISAL_MH_SHA1_MURMUR3_CTX_ERROR_NONE;

        partial_block_len = ctx->total_length % ISAL_MH_SHA1_BLOCK_SIZE;
        partial_block_buffer = ctx->partial_block_buffer;
        aligned_frame_buffer = (uint8_t *) ALIGN_64(ctx->frame_buffer);
        mh_sha1_segs_digests = (uint32_t(*)[ISAL_HASH_SEGS]) ctx->mh_sha1_interim_digests;
        murmur3_x64_128_digest = ctx->murmur3_x64_128_digest;

        ctx->total_length += len;
        // No enough input data for mh_sha1 calculation
        if (len + partial_block_len < ISAL_MH_SHA1_BLOCK_SIZE) {
                memcpy(partial_block_buffer + partial_block_len, input_data, len);
                return ISAL_MH_SHA1_MURMUR3_CTX_ERROR_NONE;
        }
        // mh_sha1 calculation for the previous partial block
        if (partial_block_len != 0) {
                memcpy(partial_block_buffer + partial_block_len, input_data,
                       ISAL_MH_SHA1_BLOCK_SIZE - partial_block_len);
                // do one_block process
                BLOCK_FUNCTION(partial_block_buffer, mh_sha1_segs_digests, aligned_frame_buffer,
                               murmur3_x64_128_digest, 1);
                input_data += ISAL_MH_SHA1_BLOCK_SIZE - partial_block_len;
                len -= ISAL_MH_SHA1_BLOCK_SIZE - partial_block_len;
                memset(partial_block_buffer, 0, ISAL_MH_SHA1_BLOCK_SIZE);
        }
        // Calculate mh_sha1 for the current blocks
        num_blocks = len / ISAL_MH_SHA1_BLOCK_SIZE;
        if (num_blocks > 0) {
                // do num_blocks process
                BLOCK_FUNCTION(input_data, mh_sha1_segs_digests, aligned_frame_buffer,
                               murmur3_x64_128_digest, num_blocks);
                len -= num_blocks * ISAL_MH_SHA1_BLOCK_SIZE;
                input_data += num_blocks * ISAL_MH_SHA1_BLOCK_SIZE;
        }
        // Store the partial block
        if (len != 0) {
                memcpy(partial_block_buffer, input_data, len);
        }

        return ISAL_MH_SHA1_MURMUR3_CTX_ERROR_NONE;
}

#ifdef UPDATE_FUNCTION_SLVER
struct slver {
        uint16_t snum;
        uint8_t ver;
        uint8_t core;
};

// Version info
struct slver _mh_sha1_murmur3_x64_128_update_base_slver_0000025a;
struct slver _mh_sha1_murmur3_x64_128_update_base_slver = { 0x025a, 0x00, 0x00 };
#endif
