/**********************************************************************
  Copyright(c) 2011-2019 Intel Corporation All rights reserved.

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

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "sm3_mb.h"
#include "endian_helper.h"
#include <openssl/evp.h>

#define TEST_LEN       (1024 * 1024ull) // 1M
#define TEST_BUFS      ISAL_SM3_MAX_LANES
#define ROTATION_TIMES 10000 // total length processing = TEST_LEN * ROTATION_TIMES
#define UPDATE_SIZE    (13 * ISAL_SM3_BLOCK_SIZE)
#define LEN_TOTAL      (TEST_LEN * ROTATION_TIMES)

/* Reference digest global to reduce stack usage */
static uint8_t digest_ref_upd[4 * ISAL_SM3_DIGEST_NWORDS];

struct user_data {
        int idx;
        uint64_t processed;
};

int
main(void)
{
        ISAL_SM3_HASH_CTX_MGR *mgr = NULL;
        ISAL_SM3_HASH_CTX ctxpool[TEST_BUFS], *ctx = NULL;
        uint32_t i, j, k, fail = 0;
        unsigned char *bufs[TEST_BUFS];
        struct user_data udata[TEST_BUFS];
        EVP_MD_CTX *md_ctx;
        const EVP_MD *md;
        unsigned int md_len;
        int ret;

        ret = posix_memalign((void *) &mgr, 16, sizeof(ISAL_SM3_HASH_CTX_MGR));
        if ((ret != 0) || (mgr == NULL)) {
                printf("posix_memalign failed test aborted\n");
                return 1;
        }

        isal_sm3_ctx_mgr_init(mgr);

        printf("sm3_large_test\n");

        // Init ctx contents
        for (i = 0; i < TEST_BUFS; i++) {
                bufs[i] = (unsigned char *) calloc((size_t) TEST_LEN, 1);
                if (bufs[i] == NULL) {
                        printf("malloc failed test aborted\n");
                        return 1;
                }
                isal_hash_ctx_init(&ctxpool[i]);
                ctxpool[i].user_data = (void *) &udata[i];
        }

        // Openssl SM3 update test
        md = EVP_sm3();
        md_ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(md_ctx, md, NULL);
        for (k = 0; k < ROTATION_TIMES; k++) {
                EVP_DigestUpdate(md_ctx, bufs[k % TEST_BUFS], TEST_LEN);
        }
        EVP_DigestFinal_ex(md_ctx, digest_ref_upd, &md_len);
        EVP_MD_CTX_free(md_ctx);

        // Initialize pool
        for (i = 0; i < TEST_BUFS; i++) {
                struct user_data *u = (struct user_data *) ctxpool[i].user_data;
                u->idx = i;
                u->processed = 0;
        }

        printf("Starting updates\n");
        int highest_pool_idx = 0;
        ctx = &ctxpool[highest_pool_idx++];
        while (ctx) {
                int len = UPDATE_SIZE;
                int update_type = ISAL_HASH_UPDATE;
                struct user_data *u = (struct user_data *) ctx->user_data;
                int idx = u->idx;

                if (u->processed == 0)
                        update_type = ISAL_HASH_FIRST;

                else if (isal_hash_ctx_complete(ctx)) {
                        if (highest_pool_idx < TEST_BUFS)
                                ctx = &ctxpool[highest_pool_idx++];
                        else
                                isal_sm3_ctx_mgr_flush(mgr, &ctx);
                        continue;
                } else if (u->processed >= (LEN_TOTAL - UPDATE_SIZE)) {
                        len = (LEN_TOTAL - u->processed);
                        update_type = ISAL_HASH_LAST;
                }
                u->processed += len;

                const int errc =
                        isal_sm3_ctx_mgr_submit(mgr, ctx, &ctx, bufs[idx], len, update_type);

                if (errc == 0 && NULL == ctx) {
                        if (highest_pool_idx < TEST_BUFS)
                                ctx = &ctxpool[highest_pool_idx++];
                        else
                                isal_sm3_ctx_mgr_flush(mgr, &ctx);
                }
        }

        printf("multibuffer SM3 digest: \n");
        for (i = 0; i < TEST_BUFS; i++) {
                printf("Total processing size of buf[%d] is %" PRIu64 "\n", i,
                       ctxpool[i].total_length);
                for (j = 0; j < ISAL_SM3_DIGEST_NWORDS; j++) {
                        printf("digest%d : %08X\n", j, ctxpool[i].job.result_digest[j]);
                }
        }
        printf("\n");

        printf("openssl SM3 update digest: \n");
        for (i = 0; i < ISAL_SM3_DIGEST_NWORDS; i++)
                printf("%08X - ", to_le32(((uint32_t *) digest_ref_upd)[i]));
        printf("\n");

        for (i = 0; i < TEST_BUFS; i++) {
                for (j = 0; j < ISAL_SM3_DIGEST_NWORDS; j++) {
                        if (ctxpool[i].job.result_digest[j] !=
                            to_le32(((uint32_t *) digest_ref_upd)[j])) {
                                fail++;
                        }
                }
        }

        if (fail)
                printf("Test failed SM3_hash_large check %d\n", fail);
        else
                printf(" SM3_hash_large_test: Pass\n");
        return fail;
}
