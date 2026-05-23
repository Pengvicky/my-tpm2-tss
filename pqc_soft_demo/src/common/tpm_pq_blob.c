#include "tpm_pq_blob.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint16_t tpm_type;
    uint8_t bytes[16];
} TpmPqTemplate;

static const TpmPqTemplate g_templates[] = {
    {
        .tpm_type = 0x88A0u,
        .bytes = {0x88, 0xA0, 0x00, 0x12, 0x00, 0x02, 0x00, 0x72,
                  0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00, 0x00},
    },
    {
        .tpm_type = 0x88A1u,
        .bytes = {0x88, 0xA1, 0x00, 0x12, 0x00, 0x02, 0x00, 0x72,
                  0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00, 0x00},
    },
    {
        .tpm_type = 0x88A2u,
        .bytes = {0x88, 0xA2, 0x00, 0x12, 0x00, 0x02, 0x00, 0x72,
                  0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00, 0x00},
    },
    {
        .tpm_type = 0x88A3u,
        .bytes = {0x88, 0xA3, 0x00, 0x12, 0x00, 0x04, 0x00, 0x72,
                  0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00, 0x00},
    },
};

static uint16_t read_be16(const uint8_t *data)
{
    return (uint16_t)((uint16_t)data[0] << 8) | data[1];
}

static uint32_t read_be32(const uint8_t *data)
{
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
        ((uint32_t)data[2] << 8) | data[3];
}

static void write_be16(uint8_t *data, uint16_t value)
{
    data[0] = (uint8_t)(value >> 8);
    data[1] = (uint8_t)(value & 0xffu);
}

static const TpmPqTemplate *find_template(uint16_t tpm_type)
{
    size_t index;

    for (index = 0; index < sizeof(g_templates) / sizeof(g_templates[0]); ++index) {
        if (g_templates[index].tpm_type == tpm_type) {
            return &g_templates[index];
        }
    }
    return NULL;
}

int tpm_pq_extract_public(const uint8_t *blob, size_t blob_len, uint8_t **raw_pub,
    size_t *raw_pub_len, TpmPqPublicInfo *info)
{
    size_t offset = 0;
    uint16_t public_size;
    uint16_t tpm_type;
    uint16_t name_alg;
    uint32_t object_attributes;
    uint16_t auth_policy_size;
    uint16_t unique_size;
    const PqAlgInfo *alg_info;
    uint8_t *copy;

    if (blob == NULL || raw_pub == NULL || raw_pub_len == NULL || blob_len < 18) {
        return -1;
    }

    public_size = read_be16(blob);
    if ((size_t)public_size + 2 != blob_len) {
        fprintf(stderr, "unexpected TPM2B_PUBLIC length: header=%u file=%zu\n",
            public_size, blob_len);
        return -1;
    }

    offset = 2;
    tpm_type = read_be16(blob + offset);
    offset += 2;
    name_alg = read_be16(blob + offset);
    offset += 2;
    object_attributes = read_be32(blob + offset);
    offset += 4;
    auth_policy_size = read_be16(blob + offset);
    offset += 2;
    if (offset + auth_policy_size + 4 + 2 > blob_len) {
        fprintf(stderr, "TPM2B_PUBLIC is truncated before unique field\n");
        return -1;
    }

    offset += auth_policy_size;
    offset += 4;
    unique_size = read_be16(blob + offset);
    offset += 2;
    if (offset + unique_size != blob_len) {
        fprintf(stderr, "TPM2B_PUBLIC unique length mismatch\n");
        return -1;
    }

    alg_info = pq_alg_info_from_tpm_public(tpm_type, unique_size);
    if (alg_info == NULL) {
        fprintf(stderr, "unsupported TPM public type 0x%04x with unique size %u\n",
            tpm_type, unique_size);
        return -1;
    }

    copy = malloc(unique_size == 0 ? 1 : unique_size);
    if (copy == NULL) {
        return -1;
    }
    if (unique_size != 0) {
        memcpy(copy, blob + offset, unique_size);
    }

    *raw_pub = copy;
    *raw_pub_len = unique_size;
    if (info != NULL) {
        info->alg_info = alg_info;
        info->tpm_type = tpm_type;
        info->name_alg = name_alg;
        info->object_attributes = object_attributes;
    }
    return 0;
}

int tpm_pq_wrap_public(const PqAlgInfo *alg_info, const uint8_t *raw_pub,
    size_t raw_pub_len, uint8_t **blob, size_t *blob_len)
{
    const TpmPqTemplate *tpl;
    uint8_t *out;
    size_t total_len;

    if (alg_info == NULL || raw_pub == NULL || blob == NULL || blob_len == NULL) {
        return -1;
    }
    if (alg_info->public_key_bytes != raw_pub_len) {
        fprintf(stderr, "raw public key length %zu does not match %s (%zu)\n",
            raw_pub_len, alg_info->name, alg_info->public_key_bytes);
        return -1;
    }

    tpl = find_template(alg_info->tpm_type);
    if (tpl == NULL) {
        fprintf(stderr, "missing TPM template for %s\n", alg_info->name);
        return -1;
    }

    total_len = 2 + sizeof(tpl->bytes) + raw_pub_len;
    out = malloc(total_len);
    if (out == NULL) {
        return -1;
    }

    write_be16(out, (uint16_t)(sizeof(tpl->bytes) + raw_pub_len));
    memcpy(out + 2, tpl->bytes, sizeof(tpl->bytes));
    write_be16(out + 2 + sizeof(tpl->bytes) - 2, (uint16_t)raw_pub_len);
    memcpy(out + 2 + sizeof(tpl->bytes), raw_pub, raw_pub_len);

    *blob = out;
    *blob_len = total_len;
    return 0;
}