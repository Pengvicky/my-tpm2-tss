#ifndef TPM_PQ_BLOB_H
#define TPM_PQ_BLOB_H

#include <stddef.h>
#include <stdint.h>

#include "pq_alg_info.h"

typedef struct {
    const PqAlgInfo *alg_info;
    uint16_t tpm_type;
    uint16_t name_alg;
    uint32_t object_attributes;
} TpmPqPublicInfo;

int tpm_pq_extract_public(const uint8_t *blob, size_t blob_len, uint8_t **raw_pub,
    size_t *raw_pub_len, TpmPqPublicInfo *info);
int tpm_pq_wrap_public(const PqAlgInfo *alg_info, const uint8_t *raw_pub,
    size_t raw_pub_len, uint8_t **blob, size_t *blob_len);

#endif