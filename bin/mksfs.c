#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <assert.h>

#include "ecc.h"

#define DEBUG
#ifdef DEBUG
#define DBG_PRINTF(...) do {\
    fprintf(stderr, ## __VA_ARGS__);\
    } while (0);
#else
    #define DBG_PRINTF(...)
#endif

#define ALIGNMENT_BITS 8 /* align files to 256-byte boundary, for DMA tx */
#define MAX_PATH_LEN 255
#define MAX_IEC_SIZE_LEN  15
#define FILE_NAME_LENGTH 200

#define _STR_FMT(s) "%" #s "s"
#define STR_FMT(s) _STR_FMT(s)

typedef struct {
    uint32_t valid;
    uint32_t offset;	/* offset in SRAM image */
    uint32_t size;
    uint32_t load_addr;		/* 32bit load address in DRAM at run-time */
    uint32_t load_addr_high; /* high 32bit of 64 bit load address in DRAM at run-time */
    char name[FILE_NAME_LENGTH];
    uint32_t entry_offset;      /* the offset of the entry point in the image */
    uint8_t checksum[SHA256_DIGEST_LENGTH];          /* SHA-256 checksum */
    uint8_t ecc[ECC_512_SIZE];                /* ecc of the struct */
} file_descriptor;

typedef struct {
    uint32_t low_mark_data;	/* low mark of data */
    uint32_t high_mark_fd;	/* high mark of file descriptors */
    uint32_t n_files;		/* number of files */
    uint32_t fsize;		/* sram file size */
    uint8_t ecc[ECC_512_SIZE];                /* ecc of the struct */
} global_table;

static int file_add (char * fname, char * fname_add, char * fname_id,
                     uint64_t load_addr64, uint32_t entry_offset);

static global_table gt;

void usage (char * executable)
{
    printf("Usage: %s <command> <filename> [command parameters] \n", executable);
    printf("'%s help' for more information\n\n", executable);
}

void show_help (char * executable)
{
    printf("Create and manipulate images of the Simple File System\n\n");
    printf("Usage: %s <command> <image_file> [command parameters] \n", executable);
    printf("\t<image_file> is the path to the file with the file system image\n\n");
    printf("<command> [command parameters] (are in hex and decimal are accepted):\n");
    printf("\tc|create <size>: creates an empty file system image "
           "(size suffix accepted)\n");
    printf("\ta|add <file> <load address> <entrypoint offset>: "
            "add a file to the image\n");
    printf("\ts|show: show content of the image\n");
    printf("\t'h|help: shows this message\n\n");
    exit(0);
}

/* like: numfmt --from=iec */
static int iectoull(uint64_t *n, const char *str)
{
    unsigned num_toks;
    char suffix;
    /* expected from caller: str has no trailing whitespace */
    num_toks = sscanf(str, "%llu%c", n, &suffix);
    if (num_toks > 1) {
        switch (suffix) {
            case 'G': *n <<= 10; /* fall-through */
            case 'M': *n <<= 10; /* fall-through */
            case 'K': *n <<= 10;
                      break;
            default:
                      fprintf(stderr, "error: invalid IEC suffix '%c' "
                              "(not in {K,M,G})\n", suffix);
                      return 1;
        }
    }
    return 0;
}

static uint32_t size32_from_str(const char *str)
{
    uint64_t val64;
    if (str[0] == '0' && str[1] == 'x')  {
        return strtoul(str, NULL, 16);
    }
    /* decimal, optionally suffixed */
    if (iectoull(&val64, str))
        exit(1);
    if (val64 >> 32) {
        fprintf(stderr, "error: size too large (32-bit max): %s", str);
        exit(1);
    }
    return val64;
}

static uint64_t addr64_from_str(const char *str)
{
    if (str[0] == '0' && str[1] == 'x')
        return strtoull(str, NULL, 16);
    else
        return strtoull(str, NULL, 10);
}

static uint32_t addr32_from_str(const char *str)
{
    uint64_t val64 = addr64_from_str(str);
    if (val64 >> 32) {
        fprintf(stderr, "error: address too large (32-bit max): %s", str);
        exit(1);
    }
    return val64;
}

void file_show (char * fname)
{
    char * buffer;
    uint32_t fsize;
    int i, j, read_size;

    FILE * fp = fopen(fname, "rb");
    if (!fp) {
        fprintf(stderr, "error: failed to open '%s': %s\n", fname, strerror(errno));
        exit(1);
    }
 
    read_size = fread(&gt, sizeof(gt), 1, fp);
    printf("========== Header of SRAM file ==========\n");
    printf(" size : 0x%x = %u bytes = %u KiB\n",
           gt.fsize, gt.fsize, gt.fsize >> 10);
    printf(" number of files: %d\n", gt.n_files);
    uint32_t space_used = gt.fsize - gt.low_mark_data + gt.high_mark_fd;
    uint32_t space_free = gt.low_mark_data - gt.high_mark_fd;
    printf(" used space: 0x%x (%u KB)\n",   space_used, space_used / 1024);
    printf(" free space: 0x%x (%u KB)\n\n", space_free, space_free / 1024);

    if (gt.n_files > 0) {
        file_descriptor * fd;
        buffer = (char *)malloc(sizeof(file_descriptor) * gt.n_files);
        read_size = fread(buffer, sizeof(file_descriptor) * gt.n_files, 1, fp);
        fd = (file_descriptor *)buffer;
        printf("--------- Files ----------\n");
        for (i = 0; i < gt.n_files; i++) {
            printf("index : %d\n", i);
            printf("\tfile name           : %s\n", fd[i].name);
            printf("\tto be loaded at     : 0x%x%x\n",
                   fd[i].load_addr_high, fd[i].load_addr);
            printf("\toffset in sram image: 0x%x\n", fd[i].offset);
            printf("\tsize                : 0x%x (%u KiB)\n",
                   fd[i].size, fd[i].size >> 10);
            printf("\tvalid               : 0x%x\n", fd[i].valid);
            printf("\tentry_offset        : 0x%x\n", fd[i].entry_offset);
            printf("\tecc                 : ");
            for (j = 0; j < 3; j++)
                printf("%02x", fd[i].ecc[j]);
            printf("\n");
            printf("\tchecksum (sha256)   : ");
            for (j = 0; j < SHA256_DIGEST_LENGTH; j++)
                printf("%02x", fd[i].checksum[j]);
            printf("\n");
        }
        free(buffer);
    }
}

int sram_file_create (char * fname, uint32_t fsize)
{
    char buffer[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint32_t i, rem;
    unsigned char * ptr, *ptr1, *ptr2;
    unsigned int data_size;

    FILE * fp = fopen(fname, "wb");
    if (!fp) {
        fprintf(stderr, "error: failed to open '%s': %s\n", fname, strerror(errno));
        return 1;
    }

    /* create dummy file */
    for (i = 0; i < fsize / 10; i++) {
        fwrite(buffer, 10, 1, fp);
    }
    rem = fsize - (10 * (fsize / 10));
    fwrite(buffer, rem, 1, fp);
    fseek(fp, 0L, SEEK_END);
    fsize = ftell(fp);

    /* high_mark_fd: end of file 
       low_mark_data :  sizeof(global_table)
       number of files: 0 */
    gt.high_mark_fd = sizeof(gt);
    gt.low_mark_data = fsize;
    gt.n_files = 0;
    gt.fsize = fsize - sizeof(gt);
    ptr1 = (unsigned char *)&gt;
    ptr2 = (unsigned char *)(gt.ecc);
    data_size = (unsigned long) ptr2 - (unsigned long) ptr1;
    assert (data_size < sizeof(gt)); 
    calculate_ecc(ptr1, data_size, ptr2);

    ptr = (char *)&gt;
    fseek(fp, 0, SEEK_SET);
    fwrite(ptr, sizeof(gt), 1, fp);

    fclose(fp);
    return 0;
}

static int sram_file_create_from_map (char * fname, uint32_t mem_size,
                                      char * fname_map, uint32_t entry_offset)
{
    FILE *fmap;
    char *line = NULL;
    size_t line_size = 0;
    ssize_t line_len = 0;
    unsigned line_num = 0;
    char mem_id[MAX_PATH_LEN + 1]; /* ignored, part of general mem map format */
    char file_id[MAX_PATH_LEN + 1];
    char file_path[MAX_PATH_LEN + 1];
    uint64_t file_addr;

     fmap = fopen(fname_map, "r");
    if (!fmap) {
        perror("failed to open map file");
        return 1;
    }

    if (sram_file_create(fname, mem_size)) {
        return 1;
    }

    while ((line_len = getline(&line, &line_size, fmap)) != -1) {
        ++line_num;
        if (line_len == 0 || line[0] == '#' ||
            ((line_len == 1 || (line_len == 2 && line[line_len - 2] == '\r') &&
             line[line_len - 1] == '\n'))) {
            free(line);
            line = NULL;
            continue;
        }
        if (sscanf(line, STR_FMT(MAX_PATH_LEN) STR_FMT(MAX_PATH_LEN)
                         " %llx " STR_FMT(MAX_PATH_LEN),
                   &mem_id, &file_id, &file_addr, &file_path) != 4) {
            fprintf(stderr, "error: %s:%u: syntax error\n", fname_map, line_num);
            free(line);
            line = NULL;
            return 1;
        }
        if (file_add(fname, file_path, file_id, file_addr, entry_offset)) {
            free(line);
            line = NULL;
            return 1;
        }
        free(line);
        line = NULL;
    }
    fclose(fmap);
    return 0;
}

int file_add (char * fname, char * fname_add, char * fname_id,
              uint64_t load_addr64, uint32_t entry_offset)
{
    FILE *fsram, *f2add;
    uint32_t i, fsize, a_offset, r_offset, rem, iter, load_addr_low, load_addr_high;
    char * ptr = (char *)&gt;
    unsigned char * ptr1, * ptr2;
    char buffer[256];
    int read_size;
    file_descriptor * fd_buf = NULL;
    unsigned int data_size;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;

    fsram = fopen(fname, "r+b");
    if (!fsram) {
        fprintf(stderr, "error: failed to open '%s': %s\n", fname, strerror(errno));
        return 1;
    }

    f2add = fopen(fname_add, "rb");
    if (!f2add) {
        fprintf(stderr, "error: failed to open '%s': %s\n", fname_add, strerror(errno));
        return 1;
    }

    /* read global table and file descriptors */
    read_size = fread(ptr, sizeof(gt), 1, fsram);
    fd_buf = (file_descriptor *)malloc(sizeof(file_descriptor) * (gt.n_files + 1));
    read_size = fread(fd_buf, sizeof(file_descriptor) * gt.n_files, 1, fsram);
    
    /* decide where to put the file */
    fseek(f2add, 0L, SEEK_END);
    fsize = ftell(f2add);
    if (fsize > gt.low_mark_data - gt.high_mark_fd) {
        printf("Error: file is too big to add\n");
        return 1;
    }
    r_offset = gt.low_mark_data - fsize;
    a_offset = r_offset;
    while (a_offset & ((1 << (ALIGNMENT_BITS)) - 1)) {
        --a_offset; --r_offset;
    }

    /* move file pointer of SRAM image */
    fseek(f2add, 0L, SEEK_SET);
    fseek(fsram, a_offset, SEEK_SET);

    /* read and write */
    iter = fsize / sizeof(buffer);
    rem  = fsize % sizeof(buffer);
    SHA256_Init(&sha256);
    for(i = 0; i < iter; i++) {
        read_size = fread(buffer, sizeof(buffer), 1, f2add);
        SHA256_Update(&sha256, buffer, sizeof(buffer));
        fwrite(buffer, sizeof(buffer), 1, fsram);
    }
    read_size = fread(buffer, rem, 1, f2add);
    SHA256_Update(&sha256, buffer, rem);
    fwrite(buffer, rem, 1, fsram);

    SHA256_Final(hash, &sha256);

    /* update global table */    
    gt.low_mark_data = r_offset;
    gt.n_files++;
    gt.high_mark_fd = sizeof(gt) + sizeof(file_descriptor) * gt.n_files;
    ptr1 = (unsigned char *)&gt;
    ptr2 = (unsigned char *)(gt.ecc);
    data_size = (unsigned long) ptr2 - (unsigned long) ptr1;
    assert (data_size < sizeof(gt)); 
    calculate_ecc(ptr1, data_size, ptr2);
    ptr = (char *)&gt;
    fseek(fsram, 0, SEEK_SET);
    fwrite(ptr, sizeof(gt), 1, fsram);

    /* update file descriptors */
    fd_buf[gt.n_files-1].valid = 1;
    fd_buf[gt.n_files-1].size = fsize;
    fd_buf[gt.n_files-1].offset = r_offset;
    fd_buf[gt.n_files-1].load_addr = load_addr64 & 0xffffffff;
    fd_buf[gt.n_files-1].load_addr_high = (load_addr64 >> 32) & 0xffffffff;
    fd_buf[gt.n_files-1].entry_offset = entry_offset;
    sprintf(fd_buf[gt.n_files-1].name,"%s", fname_id);
    memcpy(fd_buf[gt.n_files-1].checksum, hash, SHA256_DIGEST_LENGTH);

    /* calculate ECC */
    ptr1 = (unsigned char *)&fd_buf[gt.n_files-1];
    ptr2 = (unsigned char *)(fd_buf[gt.n_files-1].ecc);
    data_size = (unsigned long) ptr2 - (unsigned long) ptr1;
    calculate_ecc(ptr1, data_size, fd_buf[gt.n_files-1].ecc);

    /* write back to the file */
    ptr = (char *) fd_buf;
    fwrite(ptr, sizeof(file_descriptor) * gt.n_files, 1, fsram);
   
    free(fd_buf); 
    fclose(fsram);
    fclose(f2add);
    return 0;
}

void ram_write (unsigned char * buffer, uint32_t count, uint64_t address) {
    uint32_t i;

    unsigned char * reg_addr = (unsigned char *) address;
    for (i = 0; i < count ; i++) {
        DBG_PRINTF("%c", buffer[i]);
#ifndef DEBUG
        * reg_addr = buffer[i];
#endif
    }
}

int main (int argc, char ** argv)
{
    char *fname_sram, *fname_map, *fname_add, *fname_id, *img_size_str;
    uint64_t load_addr64;
    uint32_t img_size, entry_offset;
    int rc;

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    switch (argv[1][0]) {
        case 'c': /* create an empty image */
            if (argc != 4) { usage(argv[0]); return 1; }
            fname_sram = argv[2];
            img_size = size32_from_str(argv[3]);
            return sram_file_create(fname_sram, img_size);
        case 'a': /* add a file to the image */
            if (argc != 7) { usage(argv[0]); return 1; }
            fname_sram = argv[2];
            fname_add = argv[3];
            fname_id = argv[4];
            entry_offset = addr32_from_str(argv[6]);
            load_addr64 = addr64_from_str(argv[5]);
            return file_add(fname_sram, fname_add, fname_id,
                    load_addr64, entry_offset);
        case 'm': /* create file system image from map specification file */
            if (argc != 5) { usage(argv[0]); return 1; }
                fname_sram = argv[2];
                img_size = size32_from_str(argv[3]);
                fname_map = argv[4];
                if ((rc = sram_file_create_from_map(fname_sram, img_size, fname_map,
                                                    /* entry offset */ 0x0))) {
                    unlink(fname_sram);
                }
                return rc;
        case 's': /* show the header information */
                if (argc != 3) { usage(argv[0]); return 1; }
                fname_sram = argv[2];
                file_show(fname_sram);
                break;
        case 'h':
                show_help(argv[0]);
                break;
        default:
                usage(argv[0]);
                return 1;
    }
    return 0;
}
