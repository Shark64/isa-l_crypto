/**********************************************************************
  Copyright(c) 2024 Intel Corporation All rights reserved.

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

#include "sm3_mb.h"
#include "sm3_mb_internal.h"
#include "isal_crypto_api.h"

int
isal_sm3_ctx_mgr_init(ISAL_SM3_HASH_CTX_MGR *mgr)
{
#ifdef FIPS_MODE
        return ISAL_CRYPTO_ERR_FIPS_INVALID_ALGO;
#else
#ifdef SAFE_PARAM
        if (mgr == NULL)
                return ISAL_CRYPTO_ERR_NULL_MGR;
#endif
        _sm3_ctx_mgr_init(mgr);

        return 0;
#endif
}

int
isal_sm3_ctx_mgr_submit(ISAL_SM3_HASH_CTX_MGR *mgr, ISAL_SM3_HASH_CTX *ctx_in,
                        ISAL_SM3_HASH_CTX **ctx_out, const void *buffer, const uint32_t len,
                        const ISAL_HASH_CTX_FLAG flags)
{
#ifdef FIPS_MODE
        return ISAL_CRYPTO_ERR_FIPS_INVALID_ALGO;
#else
#ifdef SAFE_PARAM
        if (mgr == NULL)
                return ISAL_CRYPTO_ERR_NULL_MGR;
        if (ctx_in == NULL || ctx_out == NULL)
                return ISAL_CRYPTO_ERR_NULL_CTX;
        if (buffer == NULL && len != 0)
                return ISAL_CRYPTO_ERR_NULL_SRC;
#endif
        ISAL_SM3_HASH_CTX *cp = _sm3_ctx_mgr_submit(mgr, ctx_in, buffer, len, flags);

        *ctx_out = cp;

#ifdef SAFE_PARAM
        if (cp != NULL && cp->error != ISAL_HASH_CTX_ERROR_NONE) {
                if (cp->error == ISAL_HASH_CTX_ERROR_INVALID_FLAGS)
                        return ISAL_CRYPTO_ERR_INVALID_FLAGS;
                if (cp->error == ISAL_HASH_CTX_ERROR_ALREADY_PROCESSING)
                        return ISAL_CRYPTO_ERR_ALREADY_PROCESSING;
                if (cp->error == ISAL_HASH_CTX_ERROR_ALREADY_COMPLETED)
                        return ISAL_CRYPTO_ERR_ALREADY_COMPLETED;
        }
#endif
        return 0;
#endif
}

int
isal_sm3_ctx_mgr_flush(ISAL_SM3_HASH_CTX_MGR *mgr, ISAL_SM3_HASH_CTX **ctx_out)
{
#ifdef FIPS_MODE
        return ISAL_CRYPTO_ERR_FIPS_INVALID_ALGO;
#else
#ifdef SAFE_PARAM
        if (mgr == NULL)
                return ISAL_CRYPTO_ERR_NULL_MGR;
        if (ctx_out == NULL)
                return ISAL_CRYPTO_ERR_NULL_CTX;
#endif
        *ctx_out = _sm3_ctx_mgr_flush(mgr);

        return 0;
#endif
}

/*
 * =============================================================================
 * LEGACY / DEPRECATED API
 * =============================================================================
 */

void
sm3_ctx_mgr_init(ISAL_SM3_HASH_CTX_MGR *mgr)
{
        _sm3_ctx_mgr_init(mgr);
}

ISAL_SM3_HASH_CTX *
sm3_ctx_mgr_submit(ISAL_SM3_HASH_CTX_MGR *mgr, ISAL_SM3_HASH_CTX *ctx, const void *buffer,
                   uint32_t len, ISAL_HASH_CTX_FLAG flags)
{
        return _sm3_ctx_mgr_submit(mgr, ctx, buffer, len, flags);
}

ISAL_SM3_HASH_CTX *
sm3_ctx_mgr_flush(ISAL_SM3_HASH_CTX_MGR *mgr)
{
        return _sm3_ctx_mgr_flush(mgr);
}
