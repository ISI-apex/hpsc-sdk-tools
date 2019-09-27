#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "sram-image-utils.h"

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

#define _STR_FMT(s) "%" #s "s"
#define STR_FMT(s) _STR_FMT(s)

static int file_add (char * fname, char * fname_add,
                     char * fname_id, uint64_t load_addr64);

global_table gt;

void usage(char * executable)
{
    printf("Usage: %s <command> <filename> [command parameters] \n", executable);
    printf("'%s help' for more information\n\n", executable);
    exit(0);
}

void show_help(char * executable)
{
    printf("SRAM image creation utility version 1.0.\n\n");
    printf("Usage: %s <command> <filename> [command parameters] \n", executable);
    printf("\t'file name' is the SRAM chip image file name\n\n");
    printf("'command' and 'command parameters':\n");
    printf("\t'create' or 'c' creates an empty SRAM image, 'command parameters' must be <file size in either decimal or Hex>\n");
    printf("\t'add' or 'a' add a file to SRAM image, 'command parameters' must be <file name> <file name id> <load address in either decimal or Hex>\n");
    printf("\t'show' or 's' shows the header content of SRAM image, no 'command parameters' are needed\n");
    printf("\t'help' or 'h' shows this message\n\n");
    exit(0);
}

void file_show (char * fname)
{
    char * buffer;
    uint32_t fsize;
    int i, read_size;

    FILE * fp = fopen(fname, "rb");
    if (!fp) {
        fprintf(stderr, "error: failed to open '%s': %s\n", fname, strerror(errno));
        exit(1);
    }
 
    read_size = fread(&gt, sizeof(gt), 1, fp);
    printf("========== Header of SRAM file ==========\n");
    printf(" size : 0x%x\n", gt.fsize);
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
            printf("\tto be loaded at     : 0x%x%x\n", fd[i].load_addr_high, fd[i].load_addr);
            printf("\toffset in sram image: 0x%x\n", fd[i].offset);
            printf("\tsize                : 0x%x (%u KB)\n", fd[i].size, fd[i].size / 1024);
            printf("\tvalid               : 0x%x\n", fd[i].valid);
        }
        free(buffer);
    }
}

int sram_file_create (char * fname, uint32_t fsize)
{
    char buffer[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint32_t i, rem;
    char * ptr;

    FILE * fp = fopen(fname, "wb");
    if (!fp) {
        fprintf(stderr, "error: failed to open '%s': %s\n", fname, strerror(errno));
        return 1;
    }

    /* high_mark_fd: end of file 
       low_mark_data :  sizeof(global_table)
       number of files: 0 */
    gt.high_mark_fd = sizeof(gt);
    gt.low_mark_data = fsize;
    gt.n_files = 0;
    ptr = (char *)&gt;
    fwrite(ptr, sizeof(gt), 1, fp);
    fsize -= sizeof(gt);
    for (i = 0; i < fsize / 10; i++) {
        fwrite(buffer, 10, 1, fp);
    }
    rem = fsize - (10 * (fsize / 10));
    fwrite(buffer, rem, 1, fp);
    fseek(fp, 0L, SEEK_END);
    fsize = ftell(fp);
    gt.low_mark_data= fsize;
    gt.fsize = fsize;
    fseek(fp, 0L, SEEK_SET);
    fwrite(ptr, sizeof(gt), 1, fp);
    fclose(fp);
    return 0;
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

static int sram_file_create_from_map (char * fname, uint32_t mem_size, char * fname_map)
{
    FILE *fmap = fopen(fname_map, "r");
    char *line = NULL;
    size_t line_size = 0;
    ssize_t line_len = 0;
    unsigned line_num = 0;
    char mem_id[MAX_PATH_LEN + 1]; /* ignored, part of general mem map format */
    char file_id[MAX_PATH_LEN + 1];
    char file_path[MAX_PATH_LEN + 1];
    uint64_t file_addr;

    if (sram_file_create(fname, mem_size)) {
        return 1;
    }

    while ((line_len = getline(&line, &line_size, fmap)) != -1) {
        ++line_num;
        if (line_len == 0 || line[0] == '#' ||
            ((line_len == 1 || (line_len == 2 && line[line_len - 2] == '\r') &&
             line[line_len - 1] == '\n'))) {
            continue;
        }
        if (sscanf(line, STR_FMT(MAX_PATH_LEN) STR_FMT(MAX_PATH_LEN)
                         " %llx " STR_FMT(MAX_PATH_LEN),
                   &mem_id, &file_id, &file_addr, &file_path) != 4) {
            fprintf(stderr, "error: %s:%u: syntax error\n", fname_map, line_num);
            return 1;
        }
        if (file_add(fname, file_path, file_id, file_addr)) {
            return 1;
        }
    }
    fclose(fmap);
    return 0;
}

#define BUF_SIZE 256
int file_add (char * fname, char * fname_add, char * fname_id, uint64_t load_addr64)
{
    FILE *fsram, *f2add;
    uint32_t i, fsize, offset, rem, iter, load_addr_low, load_addr_high;
    char * ptr = (char *)&gt;
    char buffer[BUF_SIZE];
    int read_size;
    file_descriptor * fd_buf = NULL;

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
    fseek(fsram, 0L, SEEK_SET);
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
    offset = gt.low_mark_data - fsize;
    while (offset & ((1 << (ALIGNMENT_BITS)) - 1))
        --offset;

    /* move file pointer of SRAM image */
    fseek(f2add, 0L, SEEK_SET);
    fseek(fsram, offset, SEEK_SET);

    /* read and write */
    iter = fsize / BUF_SIZE;
    rem  = fsize % BUF_SIZE;
    for(i = 0; i < iter; i++) {
        read_size = fread(buffer, BUF_SIZE, 1, f2add);
        fwrite(buffer, BUF_SIZE, 1, fsram);
    }
    read_size = fread(buffer, rem, 1, f2add);
    fwrite(buffer, rem, 1, fsram);

    /* update global table */    
    fseek(fsram, 0L, SEEK_SET);
    gt.low_mark_data = offset;
    gt.n_files++;
    gt.high_mark_fd = sizeof(gt) + sizeof(file_descriptor) * gt.n_files;
    ptr = (char *)&gt;
    fwrite(ptr, sizeof(gt), 1, fsram);

    /* update file descriptors */
    fd_buf[gt.n_files-1].valid = 1;
    fd_buf[gt.n_files-1].size = fsize;
    fd_buf[gt.n_files-1].offset = offset;
    fd_buf[gt.n_files-1].load_addr = load_addr64 & 0xffffffff;
    fd_buf[gt.n_files-1].load_addr_high = (load_addr64 >> 32) & 0xffffffff;
    sprintf(fd_buf[gt.n_files-1].name,"%s", fname_id);
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

void file_load_all(char * fname)
{
    int i, j, read_size;
    file_descriptor fd_buf;
    unsigned char buffer[BUF_SIZE];
    unsigned char * ptr = (char *)&gt;
    FILE *fsram = fopen(fname, "rb");
    if (!fsram) {
        fprintf(stderr, "error: failed to open '%s': %s\n", fname, strerror(errno));
        exit(1);
    }

    fseek(fsram, 0L, SEEK_SET);
    read_size = fread(ptr, sizeof(gt), 1, fsram);
    for (i = 0; i < gt.n_files ; i++) {
        fseek(fsram, sizeof(gt) + sizeof(file_descriptor)*i, SEEK_SET);
        read_size = fread((char *)&fd_buf, sizeof(file_descriptor), 1, fsram);
        if (!fd_buf.valid) { i--; continue;}
        fseek(fsram, fd_buf.offset, SEEK_SET);
	DBG_PRINTF("Loading %d-th file @ (0x%x, 0x%x): name (%s), size(0x%x)\n", 
			i, fd_buf.load_addr_high, fd_buf.load_addr, fd_buf.name, fd_buf.size);
        uint32_t iter = fd_buf.size / BUF_SIZE;
        uint32_t rem  = fd_buf.size % BUF_SIZE;
        uint64_t addr = fd_buf.load_addr_high;
        addr <<= 32;
        addr += fd_buf.load_addr;
        for (j = 0; j < iter; j++, addr += BUF_SIZE) {
            read_size = fread(buffer, BUF_SIZE, 1, fsram);
            ram_write(buffer, BUF_SIZE, addr);
        }
        read_size = fread(buffer, rem, 1, fsram);
        ram_write(buffer, rem, addr);
    }
}

int main (int argc, char ** argv)
{
    char *fname_sram, *fname_map, *fname_add, *fname_id, *fsize_str, *stopstring;
    uint32_t fsize;
    uint64_t load_addr64;
    uint64_t val;
    int rc;

    if (argc < 2) {
        usage(argv[0]);
    }
    switch (argv[1][0]) {
        case 'c': /* create an empty image */
                 if (argc != 4) { usage(argv[0]); }
                 fname_sram = argv[2];
                 if (argv[3][0] == '0' && argv[3][1] == 'x') 
                     fsize = strtoul(argv[3], &stopstring, 16);
                 else 
                     fsize = strtoul(argv[3], &stopstring, 10);
                 return sram_file_create(fname_sram, fsize);
        case 'a': /* add a file to the image */
                 if (argc != 6) { usage(argv[0]); }
                 fname_sram = argv[2];
                 fname_add = argv[3];
                 fname_id = argv[4];
                 if (argv[5][0] == '0' && argv[5][1] == 'x')
                     load_addr64 = strtoul(argv[5], &stopstring, 16);
                 else
                     load_addr64 = strtoul(argv[5], &stopstring, 10);
                 return file_add(fname_sram, fname_add, fname_id, load_addr64);
        case 'm': /* create file system image from map specification file */
			if (argc != 5) { usage(argv[0]); }
				fname_sram = argv[2];
                fsize_str = argv[3];
				fname_map = argv[4];
                if (fsize_str[0] == '0' && fsize_str[1] == 'x')  {
                    fsize = strtoul(fsize_str, &stopstring, 16);
                } else  {
                    if (iectoull(&val, fsize_str))
                       return 1;
                    if (val >> 32) {
                       fprintf(stderr, "ERROR: mem size larger than 32-bit: %s\n",
                               fsize_str);
                       return 1;
                    }
                    fsize = val;
                }
				if ((rc = sram_file_create_from_map(fname_sram, fsize, fname_map))) {
                    unlink(fname_sram);
                }
                return rc;
        case 's': /* show the header information */
                 if (argc != 3) { usage(argv[0]); }
                 fname_sram = argv[2];
                 file_show(fname_sram);
                 break;
        case 'h':
                 show_help(argv[0]);
                 break;
        case 'l': /* load to the ram */
                 if (argc != 3) { usage(argv[0]); }
                 fname_sram = argv[2];
                 file_load_all(fname_sram);
                 break;
        default:
                 usage(argv[0]);
                 break;
    }
    return 0;
}
