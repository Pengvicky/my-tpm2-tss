#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pqmagic_api.h"

#include "file_util.h"
#include "pq_alg_info.h"
#include "tpm_pq_blob.h"

typedef int (*AigisKeypairFn)(unsigned char *pk, unsigned char *sk);
typedef int (*AigisSignFn)(unsigned char *sig, size_t *siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *sk);
typedef int (*AigisVerifyFn)(const unsigned char *sig, size_t siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *pk);

typedef struct {
    AigisKeypairFn keypair;
    AigisSignFn sign;
    AigisVerifyFn verify;
} AigisFns;

static uint16_t read_be16(const uint8_t *buf)
{
    return (uint16_t)(((uint16_t)buf[0] << 8) | (uint16_t)buf[1]);
}

static int streq(const char *lhs, const char *rhs)
{
    return lhs != NULL && rhs != NULL && strcmp(lhs, rhs) == 0;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage:\n"
        "  %s keygen --mode <1|2|3> --pub-out <file> --sk-out <file> [--tpm-pub-out <file>]\n"
        "  %s sign --mode <1|2|3> --sk-in <file> (--message <text> | --message-file <file>) [--sig-out <file>]\n"
        "  %s verify [--mode <1|2|3>] (--pub-in <raw> | --tpm-pub-in <tpm2b_public>) --sig-in <file> (--message <text> | --message-file <file>)\n",
        argv0, argv0, argv0);
}

static const AigisFns *get_aigis_fns(int mode)
{
    static const AigisFns mode1 = {
        .keypair = pqmagic_aigis_sig1_std_keypair,
        .sign = pqmagic_aigis_sig1_std_signature,
        .verify = pqmagic_aigis_sig1_std_verify,
    };
    static const AigisFns mode2 = {
        .keypair = pqmagic_aigis_sig2_std_keypair,
        .sign = pqmagic_aigis_sig2_std_signature,
        .verify = pqmagic_aigis_sig2_std_verify,
    };
    static const AigisFns mode3 = {
        .keypair = pqmagic_aigis_sig3_std_keypair,
        .sign = pqmagic_aigis_sig3_std_signature,
        .verify = pqmagic_aigis_sig3_std_verify,
    };

    switch (mode) {
        case 1:
            return &mode1;
        case 2:
            return &mode2;
        case 3:
            return &mode3;
        default:
            return NULL;
    }
}

static const PqAlgInfo *resolve_mode(const char *mode_text, size_t key_len, int use_secret_key)
{
    uint32_t mode = 0;

    if (mode_text != NULL) {
        if (parse_u32(mode_text, &mode) != 0) {
            return NULL;
        }
        return pq_alg_info_from_aigis_level((int)mode);
    }
    if (use_secret_key) {
        return pq_alg_info_from_aigis_secret_key_size(key_len);
    }
    return pq_alg_info_from_aigis_public_key_size(key_len);
}

static int maybe_unwrap_tpm_signature(const PqAlgInfo *alg_info,
    uint8_t **signature,
    size_t *signature_len)
{
    uint16_t sig_alg;
    uint16_t wrapped_len;
    uint8_t *raw_signature;

    if (alg_info == NULL || signature == NULL || signature_len == NULL || *signature == NULL) {
        return -1;
    }
    if (*signature_len == alg_info->signature_bytes) {
        return 0;
    }
    if (*signature_len != alg_info->signature_bytes + 4) {
        return 0;
    }

    sig_alg = read_be16(*signature);
    wrapped_len = read_be16(*signature + 2);
    if (sig_alg != alg_info->tpm_type || wrapped_len != alg_info->signature_bytes) {
        return 0;
    }

    raw_signature = malloc(alg_info->signature_bytes);
    if (raw_signature == NULL) {
        return -1;
    }
    memcpy(raw_signature, *signature + 4, alg_info->signature_bytes);
    free(*signature);
    *signature = raw_signature;
    *signature_len = alg_info->signature_bytes;
    return 1;
}

static int cmd_keygen(int argc, char **argv)
{
    const char *mode_text = NULL;
    const char *pub_path = NULL;
    const char *sk_path = NULL;
    const char *tpm_pub_path = NULL;
    const PqAlgInfo *alg_info;
    const AigisFns *fns;
    uint8_t *pub = NULL;
    uint8_t *sk = NULL;
    uint8_t *tpm_blob = NULL;
    size_t tpm_blob_len = 0;
    int index;
    int ret;
    int rc = 1;

    for (index = 2; index < argc; ++index) {
        if (streq(argv[index], "--mode") && index + 1 < argc) {
            mode_text = argv[++index];
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
    if (mode_text == NULL || pub_path == NULL || sk_path == NULL) {
        usage(argv[0]);
        goto out;
    }

    alg_info = resolve_mode(mode_text, 0, 0);
    if (alg_info == NULL) {
        fprintf(stderr, "unsupported AIGIS mode: %s\n", mode_text);
        goto out;
    }
    fns = get_aigis_fns(alg_info->level);
    if (fns == NULL) {
        goto out;
    }

    pub = malloc(alg_info->public_key_bytes);
    sk = malloc(alg_info->secret_key_bytes);
    if (pub == NULL || sk == NULL) {
        goto out;
    }

    ret = fns->keypair(pub, sk);
    if (ret != 0) {
        fprintf(stderr, "AIGIS keypair failed: ret=%d\n", ret);
        goto out;
    }
    if (write_binary_file(pub_path, pub, alg_info->public_key_bytes) != 0 ||
        write_binary_file(sk_path, sk, alg_info->secret_key_bytes) != 0) {
        goto out;
    }

    if (tpm_pub_path != NULL) {
        if (tpm_pq_wrap_public(alg_info, pub, alg_info->public_key_bytes,
                &tpm_blob, &tpm_blob_len) != 0) {
            goto out;
        }
        if (write_binary_file(tpm_pub_path, tpm_blob, tpm_blob_len) != 0) {
            goto out;
        }
    }

    printf("generated %s keypair\n", alg_info->name);
    rc = 0;
out:
    free(pub);
    free(sk);
    free(tpm_blob);
    return rc;
}

static int cmd_sign(int argc, char **argv)
{
    const char *mode_text = NULL;
    const char *sk_path = NULL;
    const char *sig_path = NULL;
    const char *message_text = NULL;
    const char *message_file = NULL;
    const PqAlgInfo *alg_info;
    const AigisFns *fns;
    uint8_t *secret_key = NULL;
    size_t secret_key_len = 0;
    uint8_t *message = NULL;
    size_t message_len = 0;
    uint8_t *signature = NULL;
    size_t signature_len = 0;
    int index;
    int ret;
    int rc = 1;

    for (index = 2; index < argc; ++index) {
        if (streq(argv[index], "--mode") && index + 1 < argc) {
            mode_text = argv[++index];
        } else if (streq(argv[index], "--sk-in") && index + 1 < argc) {
            sk_path = argv[++index];
        } else if (streq(argv[index], "--sig-out") && index + 1 < argc) {
            sig_path = argv[++index];
        } else if (streq(argv[index], "--message") && index + 1 < argc) {
            message_text = argv[++index];
        } else if (streq(argv[index], "--message-file") && index + 1 < argc) {
            message_file = argv[++index];
        } else {
            usage(argv[0]);
            goto out;
        }
    }
    if (sk_path == NULL) {
        usage(argv[0]);
        goto out;
    }

    if (read_binary_file(sk_path, &secret_key, &secret_key_len) != 0 ||
        read_message_input(message_text, message_file, &message, &message_len) != 0) {
        goto out;
    }

    alg_info = resolve_mode(mode_text, secret_key_len, 1);
    if (alg_info == NULL) {
        fprintf(stderr, "unable to resolve AIGIS mode for secret key length %zu\n", secret_key_len);
        goto out;
    }
    if (secret_key_len != alg_info->secret_key_bytes) {
        fprintf(stderr, "secret key length mismatch for %s\n", alg_info->name);
        goto out;
    }
    fns = get_aigis_fns(alg_info->level);
    if (fns == NULL) {
        goto out;
    }

    signature = malloc(alg_info->signature_bytes);
    if (signature == NULL) {
        goto out;
    }
    signature_len = alg_info->signature_bytes;

    ret = fns->sign(signature, &signature_len, message, message_len, NULL, 0, secret_key);
    if (ret != 0) {
        fprintf(stderr, "AIGIS sign failed: ret=%d\n", ret);
        goto out;
    }

    if (sig_path != NULL) {
        if (write_binary_file(sig_path, signature, signature_len) != 0) {
            goto out;
        }
    } else {
        print_hex(stdout, signature, signature_len);
    }

    printf("signed with %s\n", alg_info->name);
    rc = 0;
out:
    free(secret_key);
    free(message);
    free(signature);
    return rc;
}

static int cmd_verify(int argc, char **argv)
{
    const char *mode_text = NULL;
    const char *pub_path = NULL;
    const char *tpm_pub_path = NULL;
    const char *sig_path = NULL;
    const char *message_text = NULL;
    const char *message_file = NULL;
    const PqAlgInfo *alg_info;
    const AigisFns *fns;
    uint8_t *public_key = NULL;
    size_t public_key_len = 0;
    uint8_t *public_blob = NULL;
    size_t public_blob_len = 0;
    uint8_t *signature = NULL;
    size_t signature_len = 0;
    uint8_t *message = NULL;
    size_t message_len = 0;
    TpmPqPublicInfo info;
    int index;
    int ret;
    int rc = 1;

    memset(&info, 0, sizeof(info));
    for (index = 2; index < argc; ++index) {
        if (streq(argv[index], "--mode") && index + 1 < argc) {
            mode_text = argv[++index];
        } else if (streq(argv[index], "--pub-in") && index + 1 < argc) {
            pub_path = argv[++index];
        } else if (streq(argv[index], "--tpm-pub-in") && index + 1 < argc) {
            tpm_pub_path = argv[++index];
        } else if (streq(argv[index], "--sig-in") && index + 1 < argc) {
            sig_path = argv[++index];
        } else if (streq(argv[index], "--message") && index + 1 < argc) {
            message_text = argv[++index];
        } else if (streq(argv[index], "--message-file") && index + 1 < argc) {
            message_file = argv[++index];
        } else {
            usage(argv[0]);
            goto out;
        }
    }
    if (sig_path == NULL || ((pub_path == NULL) == (tpm_pub_path == NULL))) {
        usage(argv[0]);
        goto out;
    }

    if (tpm_pub_path != NULL) {
        if (read_binary_file(tpm_pub_path, &public_blob, &public_blob_len) != 0 ||
            tpm_pq_extract_public(public_blob, public_blob_len, &public_key, &public_key_len, &info) != 0) {
            goto out;
        }
        if (info.alg_info == NULL || info.alg_info->kind != PQ_ALG_KIND_AIGIS_SIG) {
            fprintf(stderr, "TPM public blob is not an AIGIS signing key\n");
            goto out;
        }
    } else if (read_binary_file(pub_path, &public_key, &public_key_len) != 0) {
        goto out;
    }

    if (read_binary_file(sig_path, &signature, &signature_len) != 0 ||
        read_message_input(message_text, message_file, &message, &message_len) != 0) {
        goto out;
    }

    alg_info = resolve_mode(mode_text, public_key_len, 0);
    if (alg_info == NULL) {
        fprintf(stderr, "unable to resolve AIGIS mode for public key length %zu\n", public_key_len);
        goto out;
    }
    ret = maybe_unwrap_tpm_signature(alg_info, &signature, &signature_len);
    if (ret < 0) {
        goto out;
    }
    if (ret > 0) {
        fprintf(stderr, "detected TPM/TCM-wrapped %s signature, stripped 4-byte header\n", alg_info->name);
    }
    if (signature_len != alg_info->signature_bytes) {
        fprintf(stderr, "signature length %zu does not match %s (%zu)\n",
            signature_len, alg_info->name, alg_info->signature_bytes);
        goto out;
    }
    fns = get_aigis_fns(alg_info->level);
    if (fns == NULL) {
        goto out;
    }

    ret = fns->verify(signature, signature_len, message, message_len, NULL, 0, public_key);
    if (ret != 0) {
        fprintf(stderr, "verify failed for %s: ret=%d\n", alg_info->name, ret);
        goto out;
    }

    printf("verify succeeded for %s\n", alg_info->name);
    rc = 0;
out:
    free(public_key);
    free(public_blob);
    free(signature);
    free(message);
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
    if (streq(argv[1], "sign")) {
        return cmd_sign(argc, argv);
    }
    if (streq(argv[1], "verify")) {
        return cmd_verify(argc, argv);
    }
    usage(argv[0]);
    return 1;
}