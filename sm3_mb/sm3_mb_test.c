/**********************************************************************
  Copyright(c) 2020 Arm Corporation All rights reserved.

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef FIPS_MODE
#include "sm3_mb.h"

typedef struct {
        const char *msg;
        uint32_t resultDigest[ISAL_SM3_DIGEST_NWORDS];
} TestData;

static TestData test_data[] = {
        { .msg = "abc",
          .resultDigest = { 0xf4f0c766, 0xd9edee62, 0x6bd4f2d1, 0xe2e410dc, 0x87c46741, 0xa2f7f25c,
                            0x2ba07d29, 0xe0a84b8f } },
        { .msg = "abcdabcdabcdabcdabcdabcdabcdabcd"
                 "abcdabcdabcdabcdabcdabcdabcdabcd",
          .resultDigest = { 0xf99fbede, 0xa1b87522, 0x89486038, 0x4d5a8ec1, 0xe570db6f, 0x65577e38,
                            0xa3cb3d29, 0x32570c9c }

        },
        { .msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          .resultDigest = { 0xc56c9b63, 0x379e4de6, 0x92b190a3, 0xeaa14fdf, 0x74ab2007, 0xb992f67f,
                            0x664e8cf3, 0x058c7bad } },

        { .msg = "0123456789:;<=>?@ABCDEFGHIJKLMNO",
          .resultDigest = { 0x076833d0, 0xd089ec39, 0xad857685, 0x8089797a, 0x9df9e8fd, 0x4126eb9a,
                            0xf38c22e8, 0x054bb846 } },
        { .msg = "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWX"
                 "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWX"
                 "0123456789:;<",
          .resultDigest = { 0x6cb9d38e, 0x846ac99e, 0x6d05634b, 0x3fe1bb26, 0x90368c4b, 0xee8c4299,
                            0x08c0e96a, 0x2233cdc7 } },
        { .msg = "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWX"
                 "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWX"
                 "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWX"
                 "0123456789:;<=>?@ABCDEFGHIJKLMNOPQR",
          .resultDigest = { 0x83758189, 0x050f14d1, 0x91d8a730, 0x4a2825e4, 0x11723273, 0x2114ee3f,
                            0x18cac172, 0xa9c5b07a } },
        {
                .msg = "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWX"
                       "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWX"
                       "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWX"
                       "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWX"
                       "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWX"
                       "0123456789:;<=>?",
                .resultDigest = { 0xb80f8aba, 0x55e96119, 0x851ac77b, 0xae31b3a5, 0x1333e764,
                                  0xc86ac40d, 0x34878db1, 0x7da873f6 },
        },
        { .msg = "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWX"
                 "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWX"
                 "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWX"
                 "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWX"
                 "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWX"
                 "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWX"
                 "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTU",
          .resultDigest = { 0xbd5736a7, 0x55977d13, 0xa950c78a, 0x71eeb7cb, 0xe9ef0ba5, 0x95a9302e,
                            0x155e5c33, 0xad96ce3c } },
        { .msg = "",
          .resultDigest = { 0x831db21a, 0x7fa1cf55, 0x4819618e, 0x8f1ae831, 0xc7c8be22, 0x74fbfe28,
                            0xeb35d07e, 0x2baa8250 }

        },

};

#define MSGS     sizeof(test_data) / sizeof(TestData)
#define NUM_JOBS 1000

#define PSEUDO_RANDOM_NUM(seed) ((seed) * 5 + ((seed) * (seed)) / 64) % MSGS

#define NUM_CHUNKS   4
#define DATA_BUF_LEN 4096
int
non_blocksize_updates_test(ISAL_SM3_HASH_CTX_MGR *mgr)
{
        ISAL_SM3_HASH_CTX ctx_refer;
        ISAL_SM3_HASH_CTX ctx_pool[NUM_CHUNKS];
        ISAL_SM3_HASH_CTX *ctx = NULL;

        const int update_chunks[NUM_CHUNKS] = { 32, 64, 128, 256 };
        unsigned char data_buf[DATA_BUF_LEN];

        memset(data_buf, 0xA, DATA_BUF_LEN);

        // Init contexts before first use
        isal_hash_ctx_init(&ctx_refer);

        if (isal_sm3_ctx_mgr_submit(mgr, &ctx_refer, &ctx, data_buf, DATA_BUF_LEN,
                                    ISAL_HASH_ENTIRE) != 0)
                return -1;

        if (isal_sm3_ctx_mgr_flush(mgr, &ctx) != 0)
                return -1;

        for (int c = 0; c < NUM_CHUNKS; c++) {
                const int chunk = update_chunks[c];

                isal_hash_ctx_init(&ctx_pool[c]);
                for (int i = 0; i * chunk < DATA_BUF_LEN; i++) {
                        const ISAL_HASH_CTX_FLAG flags =
                                (i == 0) ? ISAL_HASH_FIRST : ISAL_HASH_UPDATE;

                        if (isal_sm3_ctx_mgr_submit(mgr, &ctx_pool[c], &ctx, data_buf + i * chunk,
                                                    chunk, flags) != 0)
                                return -1;
                        if (isal_sm3_ctx_mgr_flush(mgr, &ctx) != 0)
                                return -1;
                }
        }

        for (int c = 0; c < NUM_CHUNKS; c++) {
                if (isal_sm3_ctx_mgr_submit(mgr, &ctx_pool[c], &ctx, NULL, 0, ISAL_HASH_LAST) != 0)
                        return -1;
                if (isal_sm3_ctx_mgr_flush(mgr, &ctx) != 0)
                        return -1;
                if (ctx_pool[c].status != ISAL_HASH_CTX_STS_COMPLETE)
                        return -1;
                for (int i = 0; i < ISAL_SM3_DIGEST_NWORDS; i++) {
                        if (ctx_refer.job.result_digest[i] != ctx_pool[c].job.result_digest[i]) {
                                printf("sm3 calc error! chunk %d, digest[%d], (%d) != (%d)\n",
                                       update_chunks[c], i, ctx_refer.job.result_digest[i],
                                       ctx_pool[c].job.result_digest[i]);
                                return -2;
                        }
                }
        }
        return 0;
}
#endif /* !FIPS_MODE */

int
main(void)
{
#ifndef FIPS_MODE
        ISAL_SM3_HASH_CTX_MGR *mgr = NULL;
        ISAL_SM3_HASH_CTX ctxpool[NUM_JOBS], *ctx = NULL;
        uint32_t i, j, k, t, checked = 0;
        uint32_t *good;
        int rc, ret = -1;
        rc = posix_memalign((void *) &mgr, 16, sizeof(ISAL_SM3_HASH_CTX_MGR));
        if (rc) {
                printf("alloc error: Fail");
                return -1;
        }
        isal_sm3_ctx_mgr_init(mgr);
        // Init contexts before first use
        for (i = 0; i < MSGS; i++) {
                isal_hash_ctx_init(&ctxpool[i]);
                ctxpool[i].user_data = (void *) ((uint64_t) i);
        }

        for (i = 0; i < MSGS; i++) {
                const int errc = isal_sm3_ctx_mgr_submit(mgr, &ctxpool[i], &ctx, test_data[i].msg,
                                                         strlen((char *) test_data[i].msg),
                                                         ISAL_HASH_ENTIRE);

                if (errc == 0) {
                        if (ctx != NULL) {
                                t = (unsigned long) (uintptr_t) (ctx->user_data);
                                good = test_data[t].resultDigest;
                                checked++;
                                for (j = 0; j < ISAL_SM3_DIGEST_NWORDS; j++) {
                                        if (good[j] != ctxpool[t].job.result_digest[j]) {
                                                printf("Test %d, digest %d is %08X, should be "
                                                       "%08X\n",
                                                       t, j, ctxpool[t].job.result_digest[j],
                                                       good[j]);
                                                goto end;
                                        }
                                }
                        }
                } else {
                        printf("Something bad happened during the submit. Error code: %d", errc);
                        goto end;
                }
        }

        while (1) {
                const int errc = isal_sm3_ctx_mgr_flush(mgr, &ctx);

                if (errc == 0) {
                        if (ctx == NULL)
                                break;

                        t = (unsigned long) (uintptr_t) (ctx->user_data);
                        good = test_data[t].resultDigest;
                        checked++;
                        for (j = 0; j < ISAL_SM3_DIGEST_NWORDS; j++) {
                                if (good[j] != ctxpool[t].job.result_digest[j]) {
                                        printf("Test %d, digest %d is %08X, should be %08X\n", t, j,
                                               ctxpool[t].job.result_digest[j], good[j]);
                                        goto end;
                                }
                        }
                } else {
                        printf("Something bad happened during the flush. Error code: %d", errc);
                        goto end;
                }
        }

        // do larger test in pseudo-random order

        // Init contexts before first use
        for (i = 0; i < NUM_JOBS; i++) {
                isal_hash_ctx_init(&ctxpool[i]);
                ctxpool[i].user_data = (void *) ((uint64_t) i);
        }

        checked = 0;
        for (i = 0; i < NUM_JOBS; i++) {
                j = PSEUDO_RANDOM_NUM(i);

                const int errc = isal_sm3_ctx_mgr_submit(mgr, &ctxpool[i], &ctx, test_data[j].msg,
                                                         strlen((char *) test_data[j].msg),
                                                         ISAL_HASH_ENTIRE);
                if (errc == 0) {
                        if (ctx != NULL) {
                                t = (unsigned long) (uintptr_t) (ctx->user_data);
                                k = PSEUDO_RANDOM_NUM(t);
                                good = test_data[k].resultDigest;
                                checked++;
                                for (j = 0; j < ISAL_SM3_DIGEST_NWORDS; j++) {
                                        if (good[j] != ctxpool[t].job.result_digest[j]) {
                                                printf("Test %d, digest %d is %08X, should be "
                                                       "%08X\n",
                                                       t, j, ctxpool[t].job.result_digest[j],
                                                       good[j]);
                                                goto end;
                                        }
                                }
                        }
                } else {
                        printf("Something bad happened during the submit. Error code: %d", errc);
                        goto end;
                }
        }
        while (1) {
                const int errc = isal_sm3_ctx_mgr_flush(mgr, &ctx);

                if (errc == 0) {
                        if (ctx == NULL)
                                break;

                        t = (unsigned long) (uintptr_t) (ctx->user_data);
                        k = PSEUDO_RANDOM_NUM(t);
                        good = test_data[k].resultDigest;
                        checked++;
                        for (j = 0; j < ISAL_SM3_DIGEST_NWORDS; j++) {
                                if (good[j] != ctxpool[t].job.result_digest[j]) {
                                        printf("Test %d, digest %d is %08X, should be %08X\n", t, j,
                                               ctxpool[t].job.result_digest[j], good[j]);
                                        goto end;
                                }
                        }
                } else {
                        printf("Something bad happened during the flush. Error code: %d", errc);
                        goto end;
                }
        }

        if (checked != NUM_JOBS) {
                printf("only tested %d rather than %d\n", checked, NUM_JOBS);
                goto end;
        }

        rc = non_blocksize_updates_test(mgr);
        if (rc) {
                printf("multi updates test fail %d\n", rc);
                goto end;
        }
        ret = 0;

        printf(" multibinary_sm3 test: Pass\n");
end:
        aligned_free(mgr);

        return ret;
#else
        printf("Not Executed\n");
        return 0;
#endif /* FIPS_MODE */
}
