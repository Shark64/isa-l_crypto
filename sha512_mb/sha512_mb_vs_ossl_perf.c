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

#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include "sha512_mb.h"
#include "test.h"

// Set number of outstanding jobs
#define TEST_BUFS 32

#ifndef GT_L3_CACHE
#define GT_L3_CACHE 32 * 1024 * 1024 /* some number > last level cache */
#endif

#if !defined(COLD_TEST) && !defined(TEST_CUSTOM)
// Cached test, loop many times over small dataset
#define TEST_LEN      4 * 1024
#define TEST_LOOPS    1000
#define TEST_TYPE_STR "_warm"
#elif defined(COLD_TEST)
// Uncached test.  Pull from large mem base.
#define TEST_LEN      (GT_L3_CACHE / TEST_BUFS)
#define TEST_LOOPS    10
#define TEST_TYPE_STR "_cold"
#endif

#define TEST_MEM TEST_LEN *TEST_BUFS *TEST_LOOPS

/* Reference digest global to reduce stack usage */
static uint8_t digest_ssl[TEST_BUFS][8 * ISAL_SHA512_DIGEST_NWORDS];

int
main(void)
{
        ISAL_SHA512_HASH_CTX_MGR *mgr = NULL;
        ISAL_SHA512_HASH_CTX ctxpool[TEST_BUFS], *ctx = NULL;
        unsigned char *bufs[TEST_BUFS];
        uint32_t i, j, t, fail = 0;
        struct perf start, stop;

        for (i = 0; i < TEST_BUFS; i++) {
                bufs[i] = (unsigned char *) calloc((size_t) TEST_LEN, 1);
                if (bufs[i] == NULL) {
                        printf("calloc failed test aborted\n");
                        return 1;
                }
                // Init ctx contents
                isal_hash_ctx_init(&ctxpool[i]);
                ctxpool[i].user_data = (void *) ((uint64_t) i);
        }

        int ret = posix_memalign((void *) &mgr, 16, sizeof(ISAL_SHA512_HASH_CTX_MGR));
        if (ret) {
                printf("alloc error: Fail");
                return -1;
        }
        ret = isal_sha512_ctx_mgr_init(mgr);
        if (ret)
                return 1;

        // Start OpenSSL tests
        perf_start(&start);
        for (t = 0; t < TEST_LOOPS; t++) {
                for (i = 0; i < TEST_BUFS; i++)
                        SHA512(bufs[i], TEST_LEN, digest_ssl[i]);
        }
        perf_stop(&stop);

        printf("sha512_openssl" TEST_TYPE_STR ": ");
        perf_print(stop, start, (long long) TEST_LEN * i * t);

        // Start mb tests
        perf_start(&start);
        for (t = 0; t < TEST_LOOPS; t++) {
                for (i = 0; i < TEST_BUFS; i++) {
                        ret = isal_sha512_ctx_mgr_submit(mgr, &ctxpool[i], &ctx, bufs[i], TEST_LEN,
                                                         ISAL_HASH_ENTIRE);
                        if (ret)
                                return 1;
                }

                do {
                        ret = isal_sha512_ctx_mgr_flush(mgr, &ctx);
                        if (ret)
                                return 1;
                } while (ctx != NULL);
        }
        perf_stop(&stop);

        printf("multibinary_sha512" TEST_TYPE_STR ": ");
        perf_print(stop, start, (long long) TEST_LEN * i * t);

        for (i = 0; i < TEST_BUFS; i++) {
                for (j = 0; j < ISAL_SHA512_DIGEST_NWORDS; j++) {
                        if (ctxpool[i].job.result_digest[j] !=
                            to_be64(((uint64_t *) digest_ssl[i])[j])) {
                                fail++;
                                printf("Test%d, digest%d fail %016lX <=> %016lX\n", i, j,
                                       ctxpool[i].job.result_digest[j],
                                       to_be64(((uint64_t *) digest_ssl[i])[j]));
                        }
                }
        }

        printf("Multi-buffer sha512 test complete %d buffers of %d B with "
               "%d iterations\n",
               TEST_BUFS, TEST_LEN, TEST_LOOPS);

        if (fail)
                printf("Test failed function check %d\n", fail);
        else
                printf("multibinary_sha512_ossl_perf: Pass\n");

        return fail;
}
