#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
        "  %s extract --in <tpm2b_public> [--raw-out <file>]\n"
        "  %s wrap [--alg <name>] --raw-in <file> --out <tpm2b_public>\n",
        argv0, argv0);
}

static int cmd_extract(int argc, char **argv)
{
    const char *input_path = NULL;
    const char *output_path = NULL;
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    uint8_t *raw_pub = NULL;
    size_t raw_pub_len = 0;
    TpmPqPublicInfo info;
    int index;
    int rc = 1;

    memset(&info, 0, sizeof(info));
    for (index = 2; index < argc; ++index) {
        if (streq(argv[index], "--in") && index + 1 < argc) {
            input_path = argv[++index];
        } else if (streq(argv[index], "--raw-out") && index + 1 < argc) {
            output_path = argv[++index];
        } else {
            usage(argv[0]);
            goto out;
        }
    }
    if (input_path == NULL) {
        usage(argv[0]);
        goto out;
    }

    if (read_binary_file(input_path, &blob, &blob_len) != 0) {
        goto out;
    }
    if (tpm_pq_extract_public(blob, blob_len, &raw_pub, &raw_pub_len, &info) != 0) {
        goto out;
    }

    printf("algorithm=%s\n", info.alg_info->name);
    printf("tpm_type=0x%04x\n", info.tpm_type);
    printf("name_alg=0x%04x\n", info.name_alg);
    printf("object_attributes=0x%08x\n", info.object_attributes);
    printf("raw_public_key_bytes=%zu\n", raw_pub_len);

    if (output_path != NULL) {
        if (write_binary_file(output_path, raw_pub, raw_pub_len) != 0) {
            goto out;
        }
    } else {
        print_hex(stdout, raw_pub, raw_pub_len);
    }

    rc = 0;
out:
    free(blob);
    free(raw_pub);
    return rc;
}

static int cmd_wrap(int argc, char **argv)
{
    const char *alg_name = NULL;
    const char *input_path = NULL;
    const char *output_path = NULL;
    const PqAlgInfo *alg_info = NULL;
    uint8_t *raw_pub = NULL;
    size_t raw_pub_len = 0;
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    int index;
    int rc = 1;

    for (index = 2; index < argc; ++index) {
        if (streq(argv[index], "--alg") && index + 1 < argc) {
            alg_name = argv[++index];
        } else if (streq(argv[index], "--raw-in") && index + 1 < argc) {
            input_path = argv[++index];
        } else if (streq(argv[index], "--out") && index + 1 < argc) {
            output_path = argv[++index];
        } else {
            usage(argv[0]);
            goto out;
        }
    }
    if (input_path == NULL || output_path == NULL) {
        usage(argv[0]);
        goto out;
    }

    if (read_binary_file(input_path, &raw_pub, &raw_pub_len) != 0) {
        goto out;
    }

    if (alg_name != NULL) {
        alg_info = pq_alg_info_by_name(alg_name);
    } else {
        alg_info = pq_alg_info_infer_from_public_key_size(raw_pub_len);
    }
    if (alg_info == NULL) {
        fprintf(stderr, "unable to determine algorithm for raw public key length %zu\n", raw_pub_len);
        goto out;
    }

    if (tpm_pq_wrap_public(alg_info, raw_pub, raw_pub_len, &blob, &blob_len) != 0) {
        goto out;
    }
    if (write_binary_file(output_path, blob, blob_len) != 0) {
        goto out;
    }

    printf("wrapped %s public key into %s (%zu bytes)\n",
        alg_info->name, output_path, blob_len);
    rc = 0;
out:
    free(raw_pub);
    free(blob);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    if (streq(argv[1], "extract")) {
        return cmd_extract(argc, argv);
    }
    if (streq(argv[1], "wrap")) {
        return cmd_wrap(argc, argv);
    }
    usage(argv[0]);
    return 1;
}