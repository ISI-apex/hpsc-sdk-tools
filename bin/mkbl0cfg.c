#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include <openssl/sha.h>

#include "ecc.h"

typedef struct bl0cfg {
    uint32_t bl1_size;
    uint32_t bl1_img_addr;  /* where copies of bl1 is stored in NVRAM */
    uint32_t bl1_load_addr;
    uint32_t bl1_entry_offset;
    unsigned char bl1_checksum[SHA256_DIGEST_LENGTH];
    unsigned char ecc[ECC_512_SIZE];
} bl0cfg;

#define MAX_PATH_LEN 255

#define _STR_FMT(s) "%" #s "s"
#define STR_FMT(s) _STR_FMT(s)

static int init_config_from_ini(struct bl0cfg *cfg, const char *bl1_file,
                                const char *ini_file)
{
    char *line = NULL;
    size_t line_size = 0;
    ssize_t line_len;
    unsigned line_num = 0;
    char section_str[MAX_PATH_LEN];
    bool have_img_addr = false, have_load_addr = false;
    bool have_entrypoint = false, have_file = false;
    int rc = 1;

    FILE * ini_fin = fopen(ini_file, "r");
    if (!ini_fin) {
        fprintf(stderr, "error: failed to open config file '%s': %s\n",
                ini_file, strerror(errno));
        return rc;
    }
    enum section {
        SECTION_IGNORE,
        SECTION_BL1,
    };
    enum section section = SECTION_IGNORE;

    while ((line_len = getline(&line, &line_size, ini_fin)) != -1) {
        ++line_num;
        /* skip comments and blank lines */
        if (line_len == 0 || line[0] == '#' ||
            ((line_len == 1 || (line_len == 2 && line[line_len - 2] == '\r') &&
                  line[line_len - 1] == '\n'))) {
            free(line);
            line = NULL;
            continue;
        }

        /* strip whitespace */
        if (line[line_len - 1] == '\n')
            line[line_len - 1] = '\0';
        if (line[line_len - 2] == '\r')
            line[line_len - 2] = '\0';

        if (!strcmp(line, "[bl1]")) {
            section = SECTION_BL1;
            free(line);
            line = NULL;
            continue;
        }
        switch (section) {
            case SECTION_BL1: 
                if (sscanf(line, "image_address = %x",
                           &cfg->bl1_img_addr) == 1) {
                    have_img_addr = true;
                } else if (sscanf(line, "load_address = %x",
                           &cfg->bl1_load_addr) == 1) {
                    have_load_addr = true;
                } else if (sscanf(line, "entrypoint_offset = %x",
                           &cfg->bl1_entry_offset) == 1) {
                    have_entrypoint = true;
                } else if (sscanf(line, "file = " STR_FMT(MAX_PATH_LEN),
                                  bl1_file) == 1) {
                    have_file = true;
                } else {
                    fprintf(stderr, "error: %s:%u: "
                            "unexpected option in [bl1] section\n",
                            ini_file, line_num);
                    goto exit;
                }
                free(line);
                line = NULL;
                continue;
            default:
                fprintf(stderr, "error: %s:%u: "
                        "option not in an expected section\n",
                        ini_file, line_num);
                goto exit;
        }
        free(line);
        line = NULL;
    }
    if (!(have_img_addr && have_load_addr && have_entrypoint && have_file)) {
        fprintf(stderr, "error: %s: incomplete config: "
                "have 'image_address': %u; have 'load_address': %u "
                "have 'entrypoint': %u; have 'file': %u\n", ini_file,
                have_img_addr, have_load_addr, have_entrypoint, have_file);
        goto exit;
    }

    rc = 0;
exit:
    if (line)
        free(line);
    fclose(ini_fin);
    return rc;
}

static void hash_file(unsigned char *hash, FILE *fin, uint32_t fsize)
{
    unsigned char buf[4096];
    int i, iter, rem, read_size;
    SHA256_CTX sha256;

    SHA256_Init(&sha256);
    iter = fsize / sizeof(buf);
    rem  = fsize % sizeof(buf);
    for(i = 0; i < iter; i++) {
        read_size = fread(buf, sizeof(buf), 1, fin);
        SHA256_Update(&sha256, buf, sizeof(buf));
    }
    read_size = fread(buf, rem, 1, fin);
    SHA256_Update(&sha256, buf, rem);
    SHA256_Final(hash, &sha256);
}

static void protect_config_with_ecc(struct bl0cfg *cfg)
{
    const unsigned char *data_ptr = (unsigned char *)cfg;
    unsigned char *ecc_ptr = (unsigned char *)(cfg->ecc);
    unsigned int data_size = (unsigned long) ecc_ptr - (unsigned long) data_ptr;
    assert (data_size < sizeof(bl0cfg)); 
    calculate_ecc(data_ptr, data_size, ecc_ptr);
}

static unsigned char *pack_le_u32(unsigned char *buf, uint32_t val)
{
    int b;
    for (b = 0; b < sizeof(uint32_t); ++b) {
        *buf++ = val;
        val >>= 8;
    }
    return buf;
}

/* pack into little endian (to match target) independent of host endianess */
static unsigned pack_config(unsigned char *buf, unsigned size,
                            const struct bl0cfg *cfg)
{
    int b;
    unsigned char *p = buf;

    assert(p < buf + size);
    p = pack_le_u32(p, cfg->bl1_size);
    assert(p < buf + size);
    p = pack_le_u32(p, cfg->bl1_img_addr);
    assert(p < buf + size);
    p = pack_le_u32(p, cfg->bl1_load_addr);
    assert(p < buf + size);
    p = pack_le_u32(p, cfg->bl1_entry_offset);

    assert(p + SHA256_DIGEST_LENGTH <= buf + size);
    memcpy(p, cfg->bl1_checksum, SHA256_DIGEST_LENGTH);
    p += SHA256_DIGEST_LENGTH;

    assert(p + ECC_512_SIZE <= buf + size);
    memcpy(p, cfg->ecc, ECC_512_SIZE);
    p += ECC_512_SIZE;

    assert(p >= buf);
    return p - buf;
}

static void show_config(struct bl0cfg *cfg)
{
    int i;
    printf("========== Config Blob ==========\n");
    printf("bl1_size = 0x%x\n", cfg->bl1_size);
    printf("bl1_img_addr = 0x%x\n", cfg->bl1_img_addr);
    printf("bl1_load_addr = 0x%x\n", cfg->bl1_load_addr);
    printf("bl1_entry_offset = 0x%x\n", cfg->bl1_entry_offset);
    printf("bl1_checksum (sha256) = ");
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) 
        printf("%02x", cfg->bl1_checksum[i]);
    printf("\n");
    printf("ecc = 0x%02x 0x%02x 0x%02x\n",
        cfg->ecc[0], cfg->ecc[1], cfg->ecc[2]);
}

int main (int argc, char ** argv)
{
    const char *ini_file, *out_file;
    const char bl1_file[MAX_PATH_LEN];
    struct bl0cfg cfg;
    unsigned char cfg_buf[512];
    unsigned cfg_buf_len;
    int rc;

    if (argc != 3) {
        fprintf(stderr, "usage: %s output_file ini_file\n", argv[0]);
        exit(1);
    }
    out_file = argv[1];
    ini_file = argv[2];

    FILE *fout = fopen(out_file, "wb");
    if (!fout) {
        fprintf(stderr, "error: failed to open output file '%s': %s\n",
                out_file, strerror(errno));
        exit(1);
    }

    rc = init_config_from_ini(&cfg, bl1_file, ini_file);
    if (rc) {
        fprintf(stderr, "error: failed to parse bl0 config file\n");
        exit(rc);
    }

    FILE *bl1_fin = fopen(bl1_file, "rb");
    if (!bl1_fin) {
        fprintf(stderr, "error: failed to open bl1 file '%s': %s\n",
                bl1_file, strerror(errno));
        return 1;
    }

    /* get size of bl1 image file */
    fseek(bl1_fin, 0L, SEEK_SET);
    fseek(bl1_fin, 0L, SEEK_END);
    cfg.bl1_size = ftell(bl1_fin);
    fseek(bl1_fin, 0L, SEEK_SET);

    hash_file(cfg.bl1_checksum, bl1_fin, cfg.bl1_size);
    fclose(bl1_fin);

    protect_config_with_ecc(&cfg);
    show_config(&cfg);
    cfg_buf_len = pack_config(cfg_buf, sizeof(cfg_buf), &cfg);

    if (fwrite((char *) cfg_buf, cfg_buf_len, 1, fout) != 1) {
        perror("write to output file failed");
        fclose(fout);
        return 1;
    }
    fclose(fout);
    return 0;
}
