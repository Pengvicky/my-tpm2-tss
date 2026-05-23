#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bsl_params.h"
#include "crypt_eal_rand.h"
#include "crypt_types.h"
#include "pqcp_types.h"
#include "scloudplus.h"

#include "file_util.h"
#include "pq_alg_info.h"
#include "tpm_pq_blob.h"

static int streq(const char *lhs, const char *rhs)
{
    return lhs != NULL && rhs != NULL && strcmp(lhs, rhs) == 0;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage:\n"
        "  %s keygen --level <128|192|256> --pub-out <file> --sk-out <file> [--tpm-pub-out <file>]\n"
        "  %s encap [--level <128|192|256>] --pub-in <file> --cipher-out <file> [--secret-out <file>]\n"
        "  %s decap [--level <128|192|256>] --sk-in <file> --cipher-in <file> [--secret-out <file>]\n",
        argv0, argv0, argv0);
}

static int scloud_level_to_alg_id(int level)
{
    switch (level) {
        case 128:
            return PQCP_SCLOUDPLUS_128;
        case 192:
            return PQCP_SCLOUDPLUS_192;
        case 256:
            return PQCP_SCLOUDPLUS_256;
        default:
            return -1;
    }
}

static const PqAlgInfo *resolve_scloud_from_level_text(const char *level_text)
{
    uint32_t level;

    if (level_text == NULL) {
        return NULL;
    }
    if (parse_u32(level_text, &level) != 0) {
        return NULL;
    }
    return pq_alg_info_from_scloud_level((int)level);
}

static int init_scloud_ctx(const PqAlgInfo *alg_info, SCLOUDPLUS_Ctx **ctx_out)
{
    SCLOUDPLUS_Ctx *ctx;
    int alg_id;
    int32_t ret;

    alg_id = scloud_level_to_alg_id(alg_info->level);
    if (alg_id < 0) {
        return -1;
    }

    ctx = (SCLOUDPLUS_Ctx *)PQCP_SCLOUDPLUS_NewCtx();
    if (ctx == NULL) {
        return -1;
    }

    ret = PQCP_SCLOUDPLUS_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &alg_id, sizeof(alg_id));
    if (ret != 0) {
        fprintf(stderr, "SCLOUD set para failed: ret=%d\n", ret);
        PQCP_SCLOUDPLUS_FreeCtx(ctx);
        return -1;
    }

    *ctx_out = ctx;
    return 0;
}

static int set_octets_param(BSL_Param *params, int32_t key, uint8_t *data, uint32_t len)
{
    params[1] = (BSL_Param)BSL_PARAM_END;
    return BSL_PARAM_InitValue(&params[0], key, BSL_PARAM_TYPE_OCTETS, data, len);
}

static int cmd_keygen(int argc, char **argv)
{
    const char *level_text = NULL;
    const char *pub_path = NULL;
    const char *sk_path = NULL;
    const char *tpm_pub_path = NULL;
    const PqAlgInfo *alg_info;
    SCLOUDPLUS_Ctx *ctx = NULL;
    uint8_t *public_key = NULL;
    uint8_t *private_key = NULL;
    uint8_t *tpm_blob = NULL;
    size_t tpm_blob_len = 0;
    BSL_Param pub_params[2];
    BSL_Param prv_params[2];
    int index;
    int32_t ret;
    int rc = 1;

    memset(pub_params, 0, sizeof(pub_params));
    memset(prv_params, 0, sizeof(prv_params));

    for (index = 2; index < argc; ++index) {
        if (streq(argv[index], "--level") && index + 1 < argc) {
            level_text = argv[++index];
        } else if (streq(argv[index], "--pub-out") && index + 1 < argc) {
            pub_path = argv[++index];
        } else if (streq(argv[index], "--sk-out") && index + 1 < argc) {
            sk_path = argv[++index];
        } else if (streq(argv[index], "--tpm-pub-out") && index + 1 < argc) {
            tpm_pub_path = argv[++index];
        } else {
            usage(argv[0]);
            goto out;
        }
    }
    if (level_text == NULL || pub_path == NULL || sk_path == NULL) {
        usage(argv[0]);
        goto out;
    }

    alg_info = resolve_scloud_from_level_text(level_text);
    if (alg_info == NULL) {
        fprintf(stderr, "unsupported SCLOUD level: %s\n", level_text);
        goto out;
    }
    if (init_scloud_ctx(alg_info, &ctx) != 0) {
        goto out;
    }

    if (CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) != 0) {
        fprintf(stderr, "CRYPT_EAL_RandInit failed\n");
        goto out;
    }
    ret = PQCP_SCLOUDPLUS_Gen(ctx);
    CRYPT_EAL_RandDeinit();
    if (ret != 0) {
        fprintf(stderr, "SCLOUD keygen failed: ret=%d\n", ret);
        goto out;
    }

    public_key = malloc(alg_info->public_key_bytes);
    private_key = malloc(alg_info->secret_key_bytes);
    if (public_key == NULL || private_key == NULL) {
        goto out;
    }
    if (set_octets_param(pub_params, PQCP_PARAM_SCLOUDPLUS_PUBKEY,
            public_key, (uint32_t)alg_info->public_key_bytes) != 0 ||
        set_octets_param(prv_params, PQCP_PARAM_SCLOUDPLUS_PRVKEY,
            private_key, (uint32_t)alg_info->secret_key_bytes) != 0) {
        goto out;
    }

    ret = PQCP_SCLOUDPLUS_GetPubKey(ctx, pub_params);
    if (ret != 0) {
        fprintf(stderr, "SCLOUD get pubkey failed: ret=%d\n", ret);
        goto out;
    }
    ret = PQCP_SCLOUDPLUS_GetPrvKey(ctx, prv_params);
    if (ret != 0) {
        fprintf(stderr, "SCLOUD get prvkey failed: ret=%d\n", ret);
        goto out;
    }

    if (write_binary_file(pub_path, public_key, alg_info->public_key_bytes) != 0 ||
        write_binary_file(sk_path, private_key, alg_info->secret_key_bytes) != 0) {
        goto out;
    }
    if (tpm_pub_path != NULL) {
        if (tpm_pq_wrap_public(alg_info, public_key, alg_info->public_key_bytes,
                &tpm_blob, &tpm_blob_len) != 0 ||
            write_binary_file(tpm_pub_path, tpm_blob, tpm_blob_len) != 0) {
            goto out;
        }
    }

    printf("generated %s keypair\n", alg_info->name);
    rc = 0;
out:
    PQCP_SCLOUDPLUS_FreeCtx(ctx);
    free(public_key);
    free(private_key);
    free(tpm_blob);
    return rc;
}

static int cmd_encap(int argc, char **argv)
{
    const char *level_text = NULL;
    const char *pub_path = NULL;
    const char *cipher_path = NULL;
    const char *secret_path = NULL;
    const PqAlgInfo *alg_info = NULL;
    SCLOUDPLUS_Ctx *ctx = NULL;
    uint8_t *public_key = NULL;
    size_t public_key_len = 0;
    uint8_t *ciphertext = NULL;
    uint8_t *secret = NULL;
    uint32_t cipher_len;
    uint32_t secret_len;
    BSL_Param pub_params[2];
    int index;
    int32_t ret;
    int rc = 1;

    memset(pub_params, 0, sizeof(pub_params));
    for (index = 2; index < argc; ++index) {
        if (streq(argv[index], "--level") && index + 1 < argc) {
            level_text = argv[++index];
        } else if (streq(argv[index], "--pub-in") && index + 1 < argc) {
            pub_path = argv[++index];
        } else if (streq(argv[index], "--cipher-out") && index + 1 < argc) {
            cipher_path = argv[++index];
        } else if (streq(argv[index], "--secret-out") && index + 1 < argc) {
            secret_path = argv[++index];
        } else {
            usage(argv[0]);
            goto out;
        }
    }
    if (pub_path == NULL || cipher_path == NULL) {
        usage(argv[0]);
        goto out;
    }

    if (read_binary_file(pub_path, &public_key, &public_key_len) != 0) {
        goto out;
    }
    if (level_text != NULL) {
        alg_info = resolve_scloud_from_level_text(level_text);
    } else {
        alg_info = pq_alg_info_from_scloud_public_key_size(public_key_len);
    }
    if (alg_info == NULL || public_key_len != alg_info->public_key_bytes) {
        fprintf(stderr, "unable to resolve SCLOUD level for public key length %zu\n", public_key_len);
        goto out;
    }
    if (init_scloud_ctx(alg_info, &ctx) != 0) {
        goto out;
    }
    if (set_octets_param(pub_params, PQCP_PARAM_SCLOUDPLUS_PUBKEY,
            public_key, (uint32_t)public_key_len) != 0) {
        goto out;
    }
    ret = PQCP_SCLOUDPLUS_SetPubKey(ctx, pub_params);
    if (ret != 0) {
        fprintf(stderr, "SCLOUD set pubkey failed: ret=%d\n", ret);
        goto out;
    }
    ret = PQCP_SCLOUDPLUS_EncapsInit(ctx, NULL);
    if (ret != 0) {
        fprintf(stderr, "SCLOUD EncapsInit failed: ret=%d\n", ret);
        goto out;
    }

    ciphertext = malloc(alg_info->ciphertext_bytes);
    secret = malloc(alg_info->shared_secret_bytes);
    if (ciphertext == NULL || secret == NULL) {
        goto out;
    }
    cipher_len = (uint32_t)alg_info->ciphertext_bytes;
    secret_len = (uint32_t)alg_info->shared_secret_bytes;

    if (CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) != 0) {
        fprintf(stderr, "CRYPT_EAL_RandInit failed\n");
        goto out;
    }
    ret = PQCP_SCLOUDPLUS_Encaps(ctx, ciphertext, &cipher_len, secret, &secret_len);
    CRYPT_EAL_RandDeinit();
    if (ret != 0) {
        fprintf(stderr, "SCLOUD encap failed: ret=%d\n", ret);
        goto out;
    }
    if (write_binary_file(cipher_path, ciphertext, cipher_len) != 0) {
        goto out;
    }
    if (secret_path != NULL) {
        if (write_binary_file(secret_path, secret, secret_len) != 0) {
            goto out;
        }
    } else {
        print_hex(stdout, secret, secret_len);
    }

    printf("encapsulated with %s\n", alg_info->name);
    rc = 0;
out:
    PQCP_SCLOUDPLUS_FreeCtx(ctx);
    free(public_key);
    free(ciphertext);
    free(secret);
    return rc;
}

static int cmd_decap(int argc, char **argv)
{
    const char *level_text = NULL;
    const char *sk_path = NULL;
    const char *cipher_path = NULL;
    const char *secret_path = NULL;
    const PqAlgInfo *alg_info = NULL;
    SCLOUDPLUS_Ctx *ctx = NULL;
    uint8_t *private_key = NULL;
    size_t private_key_len = 0;
    uint8_t *ciphertext = NULL;
    size_t ciphertext_len = 0;
    uint8_t *secret = NULL;
    uint32_t secret_len;
    BSL_Param prv_params[2];
    int index;
    int32_t ret;
    int rc = 1;

    memset(prv_params, 0, sizeof(prv_params));
    for (index = 2; index < argc; ++index) {
        if (streq(argv[index], "--level") && index + 1 < argc) {
            level_text = argv[++index];
        } else if (streq(argv[index], "--sk-in") && index + 1 < argc) {
            sk_path = argv[++index];
        } else if (streq(argv[index], "--cipher-in") && index + 1 < argc) {
            cipher_path = argv[++index];
        } else if (streq(argv[index], "--secret-out") && index + 1 < argc) {
            secret_path = argv[++index];
        } else {
            usage(argv[0]);
            goto out;
        }
    }
    if (sk_path == NULL || cipher_path == NULL) {
        usage(argv[0]);
        goto out;
    }

    if (read_binary_file(sk_path, &private_key, &private_key_len) != 0 ||
        read_binary_file(cipher_path, &ciphertext, &ciphertext_len) != 0) {
        goto out;
    }
    if (level_text != NULL) {
        alg_info = resolve_scloud_from_level_text(level_text);
    } else {
        alg_info = pq_alg_info_from_scloud_secret_key_size(private_key_len);
    }
    if (alg_info == NULL || private_key_len != alg_info->secret_key_bytes) {
        fprintf(stderr, "unable to resolve SCLOUD level for secret key length %zu\n", private_key_len);
        goto out;
    }
    if (ciphertext_len != alg_info->ciphertext_bytes) {
        fprintf(stderr, "ciphertext length %zu does not match %s (%zu)\n",
            ciphertext_len, alg_info->name, alg_info->ciphertext_bytes);
        goto out;
    }
    if (init_scloud_ctx(alg_info, &ctx) != 0) {
        goto out;
    }
    if (set_octets_param(prv_params, PQCP_PARAM_SCLOUDPLUS_PRVKEY,
            private_key, (uint32_t)private_key_len) != 0) {
        goto out;
    }
    ret = PQCP_SCLOUDPLUS_SetPrvKey(ctx, prv_params);
    if (ret != 0) {
        fprintf(stderr, "SCLOUD set prvkey failed: ret=%d\n", ret);
        goto out;
    }
    ret = PQCP_SCLOUDPLUS_DecapsInit(ctx, NULL);
    if (ret != 0) {
        fprintf(stderr, "SCLOUD DecapsInit failed: ret=%d\n", ret);
        goto out;
    }

    secret = malloc(alg_info->shared_secret_bytes);
    if (secret == NULL) {
        goto out;
    }
    secret_len = (uint32_t)alg_info->shared_secret_bytes;
    ret = PQCP_SCLOUDPLUS_Decaps(ctx, ciphertext, (uint32_t)ciphertext_len, secret, &secret_len);
    if (ret != 0) {
        fprintf(stderr, "SCLOUD decap failed: ret=%d\n", ret);
        goto out;
    }

    if (secret_path != NULL) {
        if (write_binary_file(secret_path, secret, secret_len) != 0) {
            goto out;
        }
    } else {
        print_hex(stdout, secret, secret_len);
    }

    printf("decapsulated with %s\n", alg_info->name);
    rc = 0;
out:
    PQCP_SCLOUDPLUS_FreeCtx(ctx);
    free(private_key);
    free(ciphertext);
    free(secret);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    if (streq(argv[1], "keygen")) {
        return cmd_keygen(argc, argv);
    }
    if (streq(argv[1], "encap")) {
        return cmd_encap(argc, argv);
    }
    if (streq(argv[1], "decap")) {
        return cmd_decap(argc, argv);
    }
    usage(argv[0]);
    return 1;
}