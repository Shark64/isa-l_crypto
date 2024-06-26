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
#include <stdlib.h> // for rand
#include <string.h> // for memcmp
#include <aes_gcm.h>
#include <test.h>
#include "ossl_helper.h"
#include "gcm_vectors.h"

#ifndef GT_L3_CACHE
#define GT_L3_CACHE 32 * 1024 * 1024 /* some number > last level cache */
#endif

#if !defined(COLD_TEST) && !defined(TEST_CUSTOM)
// Cached test, loop many times over small dataset
#define TEST_LEN      8 * 1024
#define TEST_LOOPS    400000
#define TEST_TYPE_STR "_warm"
#elif defined(COLD_TEST)
// Uncached test.  Pull from large mem base.
#define TEST_LEN      (2 * GT_L3_CACHE)
#define TEST_LOOPS    50
#define TEST_TYPE_STR "_cold"
#endif

#define AAD_LENGTH 16
#define TEST_MEM   TEST_LEN

static unsigned char *plaintext, *gcm_plaintext, *ciphertext, *ossl_plaintext, *ossl_ciphertext,
        *gcm_tag, *ossl_tag, *IV, *AAD;
static uint8_t key128[ISAL_GCM_128_KEY_LEN];
static uint8_t key256[ISAL_GCM_256_KEY_LEN];
uint8_t iv_len = 0;

void
mk_rand_data(uint8_t *data, uint32_t size)
{
        unsigned int i;
        for (i = 0; i < size; i++) {
                *data++ = rand();
        }
}

int
check_data(uint8_t *test, uint8_t *expected, uint64_t len, int vect, char *data_name)
{
        int mismatch;
        int OK = 1;

        mismatch = memcmp(test, expected, len);
        if (mismatch) {
                OK = 0;
                printf("  v[%d] expected results don't match %s \t\t", vect, data_name);
                {
                        uint64_t a;
                        for (a = 0; a < len; a++) {
                                if (test[a] != expected[a]) {
                                        printf(" '%x' != '%x' at %lx of %lx\n", test[a],
                                               expected[a], a, len);
                                        break;
                                }
                        }
                }
        }
        return OK;
}

void
aes_gcm_perf(void)
{
        struct isal_gcm_key_data gkey, gkey256;
        struct isal_gcm_context_data gctx;
        int i;

        printf("AES GCM performance parameters plain text length:%d; IV length:%d; ADD length:%d "
               "\n",
               TEST_LEN, ISAL_GCM_IV_LEN, AAD_LENGTH);

        mk_rand_data(key128, sizeof(key128));
        mk_rand_data(key256, sizeof(key256));

        // This is only required once for a given key
        isal_aes_gcm_pre_128(key128, &gkey);
        isal_aes_gcm_pre_256(key256, &gkey256);

        // Preload code cache
        isal_aes_gcm_enc_128(&gkey, &gctx, ciphertext, plaintext, TEST_LEN, IV, AAD, AAD_LENGTH,
                             gcm_tag, ISAL_GCM_MAX_TAG_LEN);
        openssl_aes_gcm_enc(key128, IV, iv_len, AAD, AAD_LENGTH, ossl_tag, ISAL_GCM_MAX_TAG_LEN,
                            plaintext, TEST_LEN, ossl_ciphertext);
        check_data(ciphertext, ossl_ciphertext, TEST_LEN, 0,
                   "ISA-L vs OpenSSL 128 key cypher text (C)");
        check_data(gcm_tag, ossl_tag, ISAL_GCM_MAX_TAG_LEN, 0, "ISA-L vs OpenSSL 128 tag (T)");
        isal_aes_gcm_enc_256(&gkey256, &gctx, ciphertext, plaintext, TEST_LEN, IV, AAD, AAD_LENGTH,
                             gcm_tag, ISAL_GCM_MAX_TAG_LEN);
        openssl_aes_256_gcm_enc(key256, IV, iv_len, AAD, AAD_LENGTH, ossl_tag, ISAL_GCM_MAX_TAG_LEN,
                                plaintext, TEST_LEN, ossl_ciphertext);
        check_data(ciphertext, ossl_ciphertext, TEST_LEN, 0,
                   "ISA-L vs OpenSSL 256 cypher text (C)");
        check_data(gcm_tag, ossl_tag, ISAL_GCM_MAX_TAG_LEN, 0, "ISA-L vs OpenSSL 256 tag (T)");

        {
                struct perf start, stop;

                perf_start(&start);
                for (i = 0; i < TEST_LOOPS; i++) {
                        isal_aes_gcm_enc_128(&gkey, &gctx, ciphertext, plaintext, TEST_LEN, IV, AAD,
                                             AAD_LENGTH, gcm_tag, ISAL_GCM_MAX_TAG_LEN);
                }

                perf_stop(&stop);
                printf("        isal_aes_gcm_enc" TEST_TYPE_STR ":\t");
                perf_print(stop, start, (long long) TEST_LEN * i);
        }
        {
                struct perf start, stop;

                perf_start(&start);
                for (i = 0; i < TEST_LOOPS; i++) {
                        openssl_aes_gcm_enc(key128, IV, iv_len, AAD, AAD_LENGTH, ossl_tag,
                                            ISAL_GCM_MAX_TAG_LEN, plaintext, TEST_LEN, ciphertext);
                }

                perf_stop(&stop);
                printf("openssl_aes_gcm_enc" TEST_TYPE_STR ":\t");
                perf_print(stop, start, (long long) TEST_LEN * i);
        }
        {
                struct perf start, stop;

                perf_start(&start);
                for (i = 0; i < TEST_LOOPS; i++) {
                        isal_aes_gcm_dec_128(&gkey, &gctx, plaintext, ciphertext, TEST_LEN, IV, AAD,
                                             AAD_LENGTH, gcm_tag, ISAL_GCM_MAX_TAG_LEN);
                        check_data(gcm_tag, gcm_tag, ISAL_GCM_MAX_TAG_LEN, 0,
                                   "ISA-L check of tag (T)");
                }

                perf_stop(&stop);
                printf("        isal_aes_gcm_dec" TEST_TYPE_STR ":\t");
                perf_print(stop, start, (long long) TEST_LEN * i);
        }
        {
                struct perf start, stop;

                perf_start(&start);
                for (i = 0; i < TEST_LOOPS; i++) {
                        openssl_aes_gcm_dec(key128, IV, iv_len, AAD, AAD_LENGTH, ossl_tag,
                                            ISAL_GCM_MAX_TAG_LEN, ciphertext, TEST_LEN, plaintext);
                }

                perf_stop(&stop);
                printf("openssl_aes_gcm_dec" TEST_TYPE_STR ":\t");
                perf_print(stop, start, (long long) TEST_LEN * i);
        }

        printf("\n");
        {
                struct perf start, stop;

                perf_start(&start);
                for (i = 0; i < TEST_LOOPS; i++) {
                        isal_aes_gcm_enc_256(&gkey256, &gctx, ciphertext, plaintext, TEST_LEN, IV,
                                             AAD, AAD_LENGTH, gcm_tag, ISAL_GCM_MAX_TAG_LEN);
                }

                perf_stop(&stop);
                printf("         aes_gcm256_enc" TEST_TYPE_STR ":\t");
                perf_print(stop, start, (long long) TEST_LEN * i);
        }

        {
                struct perf start, stop;

                perf_start(&start);
                for (i = 0; i < TEST_LOOPS; i++) {
                        openssl_aes_256_gcm_enc(key256, IV, iv_len, AAD, AAD_LENGTH, ossl_tag,
                                                ISAL_GCM_MAX_TAG_LEN, plaintext, TEST_LEN,
                                                ciphertext);
                }

                perf_stop(&stop);
                printf("openssl_aes_256_gcm_enc" TEST_TYPE_STR ":\t");
                perf_print(stop, start, (long long) TEST_LEN * i);
        }

        {
                struct perf start, stop;

                perf_start(&start);
                for (i = 0; i < TEST_LOOPS; i++) {
                        isal_aes_gcm_dec_256(&gkey256, &gctx, plaintext, ciphertext, TEST_LEN, IV,
                                             AAD, AAD_LENGTH, gcm_tag, ISAL_GCM_MAX_TAG_LEN);
                        check_data(gcm_tag, gcm_tag, ISAL_GCM_MAX_TAG_LEN, 0,
                                   "ISA-L check of 256 tag (T)");
                }

                perf_stop(&stop);
                printf("         aes_gcm256_dec" TEST_TYPE_STR ":\t");
                perf_print(stop, start, (long long) TEST_LEN * i);
        }
        {
                struct perf start, stop;

                perf_start(&start);
                for (i = 0; i < TEST_LOOPS; i++) {
                        openssl_aes_256_gcm_dec(key256, IV, iv_len, AAD, AAD_LENGTH, ossl_tag,
                                                ISAL_GCM_MAX_TAG_LEN, ciphertext, TEST_LEN,
                                                plaintext);
                }

                perf_stop(&stop);
                printf("openssl_aes_256_gcm_dec" TEST_TYPE_STR ":\t");
                perf_print(stop, start, (long long) TEST_LEN * i);
        }
}

int
main(void)
{
        uint32_t OK = 1;

        plaintext = malloc(TEST_LEN);
        gcm_plaintext = malloc(TEST_LEN);
        ciphertext = malloc(TEST_LEN);
        ossl_plaintext = malloc(TEST_LEN + 16);
        ossl_ciphertext = malloc(TEST_LEN);
        gcm_tag = malloc(ISAL_GCM_MAX_TAG_LEN);
        ossl_tag = malloc(ISAL_GCM_MAX_TAG_LEN);
        AAD = malloc(AAD_LENGTH);
        IV = malloc(ISAL_GCM_IV_LEN);
        if ((NULL == plaintext) || (NULL == ciphertext) || (NULL == gcm_plaintext) ||
            (NULL == ossl_plaintext) || (NULL == ossl_ciphertext) || (NULL == gcm_tag) ||
            (NULL == ossl_tag) || (NULL == AAD) || (NULL == IV)) {
                printf("malloc of testsize:0x%x failed\n", TEST_LEN);
                return -1;
        }

        mk_rand_data(plaintext, TEST_LEN);
        mk_rand_data(AAD, AAD_LENGTH);
        mk_rand_data(IV, ISAL_GCM_IV_LEN);
        iv_len = ISAL_GCM_IV_LEN;

        aes_gcm_perf();
        printf("AES gcm ISA-L vs OpenSSL performance\n");

        return !OK;
}
