#include "pq_alg_info.h"

#include <string.h>

#include "pqmagic_api.h"

#define TPM_ALG_SCLOUDPLUS_L1 0x88A0u
#define TPM_ALG_SCLOUDPLUS_L3 0x88A1u
#define TPM_ALG_SCLOUDPLUS_L5 0x88A2u
#define TPM_ALG_AIGIS_SIG     0x88A3u

static const PqAlgInfo g_algorithms[] = {
    {
        .kind = PQ_ALG_KIND_AIGIS_SIG,
        .level = 1,
        .name = "aigis1",
        .public_key_bytes = AIGIS_SIG1_PUBLICKEYBYTES,
        .secret_key_bytes = AIGIS_SIG1_SECRETKEYBYTES,
        .signature_bytes = AIGIS_SIG1_SIGBYTES,
        .ciphertext_bytes = 0,
        .shared_secret_bytes = 0,
        .tpm_type = TPM_ALG_AIGIS_SIG,
    },
    {
        .kind = PQ_ALG_KIND_AIGIS_SIG,
        .level = 2,
        .name = "aigis2",
        .public_key_bytes = AIGIS_SIG2_PUBLICKEYBYTES,
        .secret_key_bytes = AIGIS_SIG2_SECRETKEYBYTES,
        .signature_bytes = AIGIS_SIG2_SIGBYTES,
        .ciphertext_bytes = 0,
        .shared_secret_bytes = 0,
        .tpm_type = TPM_ALG_AIGIS_SIG,
    },
    {
        .kind = PQ_ALG_KIND_AIGIS_SIG,
        .level = 3,
        .name = "aigis3",
        .public_key_bytes = AIGIS_SIG3_PUBLICKEYBYTES,
        .secret_key_bytes = AIGIS_SIG3_SECRETKEYBYTES,
        .signature_bytes = AIGIS_SIG3_SIGBYTES,
        .ciphertext_bytes = 0,
        .shared_secret_bytes = 0,
        .tpm_type = TPM_ALG_AIGIS_SIG,
    },
    {
        .kind = PQ_ALG_KIND_SCLOUDPLUS,
        .level = 128,
        .name = "scloud128",
        .public_key_bytes = 7216,
        .secret_key_bytes = 8480,
        .signature_bytes = 0,
        .ciphertext_bytes = 5456,
        .shared_secret_bytes = 16,
        .tpm_type = TPM_ALG_SCLOUDPLUS_L1,
    },
    {
        .kind = PQ_ALG_KIND_SCLOUDPLUS,
        .level = 192,
        .name = "scloud192",
        .public_key_bytes = 11152,
        .secret_key_bytes = 13008,
        .signature_bytes = 0,
        .ciphertext_bytes = 10832,
        .shared_secret_bytes = 24,
        .tpm_type = TPM_ALG_SCLOUDPLUS_L3,
    },
    {
        .kind = PQ_ALG_KIND_SCLOUDPLUS,
        .level = 256,
        .name = "scloud256",
        .public_key_bytes = 18760,
        .secret_key_bytes = 21904,
        .signature_bytes = 0,
        .ciphertext_bytes = 16916,
        .shared_secret_bytes = 32,
        .tpm_type = TPM_ALG_SCLOUDPLUS_L5,
    },
};

static int streq(const char *lhs, const char *rhs)
{
    return lhs != NULL && rhs != NULL && strcmp(lhs, rhs) == 0;
}

static const PqAlgInfo *find_by_kind_level(PqAlgKind kind, int level)
{
    size_t index;

    for (index = 0; index < sizeof(g_algorithms) / sizeof(g_algorithms[0]); ++index) {
        if (g_algorithms[index].kind == kind && g_algorithms[index].level == level) {
            return &g_algorithms[index];
        }
    }
    return NULL;
}

static const PqAlgInfo *find_by_size(PqAlgKind kind, size_t bytes, int use_secret_key)
{
    size_t index;

    for (index = 0; index < sizeof(g_algorithms) / sizeof(g_algorithms[0]); ++index) {
        if (g_algorithms[index].kind != kind) {
            continue;
        }
        if ((!use_secret_key && g_algorithms[index].public_key_bytes == bytes) ||
            (use_secret_key && g_algorithms[index].secret_key_bytes == bytes)) {
            return &g_algorithms[index];
        }
    }
    return NULL;
}

const PqAlgInfo *pq_alg_info_by_name(const char *name)
{
    size_t index;

    if (name == NULL) {
        return NULL;
    }
    for (index = 0; index < sizeof(g_algorithms) / sizeof(g_algorithms[0]); ++index) {
        if (streq(name, g_algorithms[index].name)) {
            return &g_algorithms[index];
        }
    }

    if (streq(name, "aigis-sig1")) {
        return pq_alg_info_from_aigis_level(1);
    }
    if (streq(name, "aigis-sig2")) {
        return pq_alg_info_from_aigis_level(2);
    }
    if (streq(name, "aigis-sig3")) {
        return pq_alg_info_from_aigis_level(3);
    }
    if (streq(name, "scloudplus128")) {
        return pq_alg_info_from_scloud_level(128);
    }
    if (streq(name, "scloudplus192")) {
        return pq_alg_info_from_scloud_level(192);
    }
    if (streq(name, "scloudplus256")) {
        return pq_alg_info_from_scloud_level(256);
    }
    return NULL;
}

const PqAlgInfo *pq_alg_info_from_aigis_level(int level)
{
    return find_by_kind_level(PQ_ALG_KIND_AIGIS_SIG, level);
}

const PqAlgInfo *pq_alg_info_from_aigis_public_key_size(size_t bytes)
{
    return find_by_size(PQ_ALG_KIND_AIGIS_SIG, bytes, 0);
}

const PqAlgInfo *pq_alg_info_from_aigis_secret_key_size(size_t bytes)
{
    return find_by_size(PQ_ALG_KIND_AIGIS_SIG, bytes, 1);
}

const PqAlgInfo *pq_alg_info_from_scloud_level(int level)
{
    return find_by_kind_level(PQ_ALG_KIND_SCLOUDPLUS, level);
}

const PqAlgInfo *pq_alg_info_from_scloud_public_key_size(size_t bytes)
{
    return find_by_size(PQ_ALG_KIND_SCLOUDPLUS, bytes, 0);
}

const PqAlgInfo *pq_alg_info_from_scloud_secret_key_size(size_t bytes)
{
    return find_by_size(PQ_ALG_KIND_SCLOUDPLUS, bytes, 1);
}

const PqAlgInfo *pq_alg_info_from_tpm_public(uint16_t tpm_type, size_t unique_bytes)
{
    if (tpm_type == TPM_ALG_AIGIS_SIG) {
        return pq_alg_info_from_aigis_public_key_size(unique_bytes);
    }
    if (tpm_type == TPM_ALG_SCLOUDPLUS_L1) {
        return pq_alg_info_from_scloud_level(128);
    }
    if (tpm_type == TPM_ALG_SCLOUDPLUS_L3) {
        return pq_alg_info_from_scloud_level(192);
    }
    if (tpm_type == TPM_ALG_SCLOUDPLUS_L5) {
        return pq_alg_info_from_scloud_level(256);
    }
    return NULL;
}

const PqAlgInfo *pq_alg_info_infer_from_public_key_size(size_t bytes)
{
    const PqAlgInfo *info;

    info = pq_alg_info_from_aigis_public_key_size(bytes);
    if (info != NULL) {
        return info;
    }
    return pq_alg_info_from_scloud_public_key_size(bytes);
}