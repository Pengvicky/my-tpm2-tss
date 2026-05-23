#ifndef PQ_ALG_INFO_H
#define PQ_ALG_INFO_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    PQ_ALG_KIND_UNKNOWN = 0,
    PQ_ALG_KIND_AIGIS_SIG,
    PQ_ALG_KIND_SCLOUDPLUS,
} PqAlgKind;

typedef struct {
    PqAlgKind kind;
    int level;
    const char *name;
    size_t public_key_bytes;
    size_t secret_key_bytes;
    size_t signature_bytes;
    size_t ciphertext_bytes;
    size_t shared_secret_bytes;
    uint16_t tpm_type;
} PqAlgInfo;

const PqAlgInfo *pq_alg_info_by_name(const char *name);
const PqAlgInfo *pq_alg_info_from_aigis_level(int level);
const PqAlgInfo *pq_alg_info_from_aigis_public_key_size(size_t bytes);
const PqAlgInfo *pq_alg_info_from_aigis_secret_key_size(size_t bytes);
const PqAlgInfo *pq_alg_info_from_scloud_level(int level);
const PqAlgInfo *pq_alg_info_from_scloud_public_key_size(size_t bytes);
const PqAlgInfo *pq_alg_info_from_scloud_secret_key_size(size_t bytes);
const PqAlgInfo *pq_alg_info_from_tpm_public(uint16_t tpm_type, size_t unique_bytes);
const PqAlgInfo *pq_alg_info_infer_from_public_key_size(size_t bytes);

#endif