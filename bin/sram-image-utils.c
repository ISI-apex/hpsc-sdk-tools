#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <openssl/sha.h>
#include <assert.h>
#include "ecc.h"
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

/* Layout of NVRAM */
#define BL0_SECTION_LIMIT	0x300000
#define BL_FS_START		BL0_SECTION_LIMIT

#define CONFIG_BL0_BLOB_START	0x0	

/* TODO: TRCH_FS_START is not used yet */
#define TRCH_FS_START		0x800000

#define BL1_COPIES      0x3
#define SHA256_CHECKSUM_SIZE 32

/* TODO: Triple copies of BL0_BLOB */
#define BLOB_ADDR0      0x0
#define BLOB_ADDR1      0x1000000
#define BLOB_ADDR2      0x2000000

#define cp_checksum(dest,src) 		\
{ 						\
    int i;					\
    for (i = 0; i < 32; i++) 			\
        dest[i] = src[i];	\
}						\

typedef struct {
    uint32_t bl1_size;
    uint32_t bl1_start;  /* where copies of bl1 is stored in NVRAM */
    uint32_t bl1_load_addr;
    uint32_t bl1_entry_offset;
    unsigned char checksum[SHA256_CHECKSUM_SIZE];
    unsigned char ecc[ECC_512_SIZE];
} bl0_blob;

global_table gt;

void usage (char * executable)
{
    printf("Usage: %s <command> <filename> [command parameters] \n", executable);
    printf("'%s help' for more information\n\n", executable);
    exit(0);
}

void show_help (char * executable)
{
    printf("SRAM image creation utility version 1.0.\n\n");
    printf("Usage: %s <command> <filename> [command parameters] \n", executable);
    printf("\t'file name' is the SRAM chip image file name\n\n");
    printf("'command' and 'command parameters':\n");
    printf("\t'create' or 'c' creates an empty SRAM image, 'command parameters' must be <file size in either decimal or Hex>\n");
    printf("\t'add' or 'a' add a file to SRAM image, 'command parameters' must be <file name> <load address in either decimal or Hex> <offset of the entry in either decimal or Hex\n");
    printf("\t'blob' or 'b' configures configuration blob with bl1 image, 'command parameters' must be <bl1 image file> <load addr in either decimal or Hex> <entry offset in either decimal or Hex>\n");
    printf("\t'show' or 's' shows the header content of SRAM image, no 'command parameters' are needed\n");
    printf("\t'help' or 'h' shows this message\n\n");
    exit(0);
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
 
    bl0_blob config_blob;
    fseek(fp, BLOB_ADDR0, SEEK_SET); 
    read_size = fread(&config_blob, sizeof(config_blob), 1, fp);
    printf("========== Config Blob ==========\n");
    printf("bl1_size = 0x%x\n", config_blob.bl1_size);
    printf("bl1_start = 0x%x\n", config_blob.bl1_start);
    printf("bl1_load_addr = 0x%x\n", config_blob.bl1_load_addr);
    printf("bl1_entry_offset = 0x%x\n", config_blob.bl1_entry_offset);
    printf("ecc = 0x%2x 0x%2x 0x%2x\n", config_blob.ecc[0], config_blob.ecc[1], config_blob.ecc[2]);
    for (i = 0; i < 32; i++) 
        printf("%02x", config_blob.checksum[i]);
    printf("\n\n");
    
    fseek(fp, BL_FS_START, SEEK_SET); 
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
            printf("\toffset in sram image: 0x%x\n", fd[i].offset + BL_FS_START);
            printf("\tsize                : 0x%x (%u KB)\n", fd[i].size, fd[i].size / 1024);
            printf("\tvalid               : 0x%x\n", fd[i].valid);
            printf("\tentry_offset	  : 0x%x\n", fd[i].entry_offset);
            printf("\tecc		  : ");
	    for (j = 0; j < 3; j++)
                printf("%02x", fd[i].ecc[j]);
            printf("\n\tchecksum		  : \n\t                       ");
	    for (j = 0; j < 32; j++)
                printf("%02x", fd[i].checksum[j]);
            printf("\n");
        }
        free(buffer);
    }
}

void sram_file_create (char * fname, uint32_t fsize)
{
    char buffer[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint32_t i, rem;
    unsigned char * ptr, *ptr1, *ptr2;
    unsigned int data_size;

    FILE * fp = fopen(fname, "wb");
    if (!fp) {
        fprintf(stderr, "error: failed to open '%s': %s\n", fname, strerror(errno));
        exit(1);
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
    gt.low_mark_data = fsize - BL_FS_START;
    gt.n_files = 0;
    gt.fsize = fsize - (sizeof(gt) + BL_FS_START);
    ptr1 = (unsigned char *)&gt;
    ptr2 = (unsigned char *)(gt.ecc);
    data_size = (unsigned long) ptr2 - (unsigned long) ptr1;
    assert (data_size < sizeof(gt)); 
    calculate_ecc(ptr1, data_size, ptr2);

    ptr = (char *)&gt;
    fseek(fp, BL_FS_START, SEEK_SET);	
    fwrite(ptr, sizeof(gt), 1, fp);

    fclose(fp);
}

#define BUF_SIZE 256
void file_add (char * fname, char * fname_add, char * fname_id, uint64_t load_addr64, uint32_t entry_offset)
{
    FILE *fsram, *f2add;
    uint32_t i, fsize, a_offset, r_offset, rem, iter, load_addr_low, load_addr_high;
    char * ptr = (char *)&gt;
    unsigned char * ptr1, * ptr2;
    char buffer[BUF_SIZE];
    int read_size;
    file_descriptor * fd_buf = NULL;
    unsigned int data_size;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;

    fsram = fopen(fname, "r+b");
    if (!fsram) {
        fprintf(stderr, "error: failed to open '%s': %s\n", fname, strerror(errno));
        exit(1);
    }

    f2add = fopen(fname_add, "rb");
    if (!f2add) {
        fprintf(stderr, "error: failed to open '%s': %s\n", fname_add, strerror(errno));
        exit(1);
    }

    /* read global table and file descriptors */
    fseek(fsram, BL_FS_START, SEEK_SET);
    read_size = fread(ptr, sizeof(gt), 1, fsram);
    fd_buf = (file_descriptor *)malloc(sizeof(file_descriptor) * (gt.n_files + 1));
    read_size = fread(fd_buf, sizeof(file_descriptor) * gt.n_files, 1, fsram);
    
    /* decide where to put the file */
    fseek(f2add, 0L, SEEK_END);
    fsize = ftell(f2add);
    if (fsize > gt.low_mark_data - gt.high_mark_fd) {
        printf("Error: file is too big to add\n");
        exit(1);
    }
    r_offset = gt.low_mark_data - fsize;
    a_offset = r_offset + BL_FS_START;
    while (a_offset & ((1 << (ALIGNMENT_BITS)) - 1)) {
        --a_offset; --r_offset;
    }

    /* move file pointer of SRAM image */
    fseek(f2add, 0L, SEEK_SET);
    fseek(fsram, a_offset, SEEK_SET);

    /* read and write */
    iter = fsize / BUF_SIZE;
    rem  = fsize % BUF_SIZE;
    SHA256_Init(&sha256);
    for(i = 0; i < iter; i++) {
        read_size = fread(buffer, BUF_SIZE, 1, f2add);
        SHA256_Update(&sha256, buffer, BUF_SIZE);
        fwrite(buffer, BUF_SIZE, 1, fsram);
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
    fseek(fsram, BL_FS_START, SEEK_SET);
    fwrite(ptr, sizeof(gt), 1, fsram);

    /* update file descriptors */
    fd_buf[gt.n_files-1].valid = 1;
    fd_buf[gt.n_files-1].size = fsize;
    fd_buf[gt.n_files-1].offset = r_offset;
    fd_buf[gt.n_files-1].load_addr = load_addr64 & 0xffffffff;
    fd_buf[gt.n_files-1].load_addr_high = (load_addr64 >> 32) & 0xffffffff;
    fd_buf[gt.n_files-1].entry_offset = entry_offset;
    sprintf(fd_buf[gt.n_files-1].name,"%s", fname_id);
    cp_checksum(fd_buf[gt.n_files-1].checksum, hash);
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
        fseek(fsram, fd_buf.offset + BL_FS_START, SEEK_SET);
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

void cp_blob(bl0_blob * config_blob, char * fname_sram, char * fname, unsigned long load_addr, unsigned long entry_offset)
{
    int i, iter, rem, read_size;
    unsigned char * ptr1, * ptr2;
    unsigned int data_size, bl1_size, blob_size;
    unsigned char buffer[BUF_SIZE];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    FILE * fp = fopen(fname_sram, "r+b");
    FILE * fp_read = fopen(fname, "rb");

    if (!fp) {
        fprintf(stderr, "error: failed to open file '%s': %s\n", fname_sram, strerror(errno));
        exit(1);
    }
    if (!fp_read) {
        fprintf(stderr, "error: failed to open file '%s': %s\n", fname, strerror(errno));
        exit(1);
    }

    fseek(fp, 0L, SEEK_SET);
    fseek(fp_read, 0L, SEEK_SET);
    fseek(fp_read, 0L, SEEK_END);
    bl1_size = ftell(fp_read);

    blob_size = sizeof(bl0_blob);
    if (blob_size % (1 << ALIGNMENT_BITS)) {	/* align in ALIGNMENT_BITS */
        blob_size = ((blob_size >> ALIGNMENT_BITS) + 1) << ALIGNMENT_BITS;
    }
    assert(blob_size + bl1_size < BL0_SECTION_LIMIT);

    /* read and write */
    iter = bl1_size / BUF_SIZE;
    rem  = bl1_size % BUF_SIZE;
    SHA256_Init(&sha256);
    fseek(fp_read, 0L, SEEK_SET);
    fseek(fp, blob_size, SEEK_SET);
    for(i = 0; i < iter; i++) {
        read_size = fread(buffer, BUF_SIZE, 1, fp_read);
        SHA256_Update(&sha256, buffer, BUF_SIZE);
        fwrite(buffer, BUF_SIZE, 1, fp);
    }
    read_size = fread(buffer, rem, 1, fp_read);
    SHA256_Update(&sha256, buffer, rem);
    fwrite(buffer, rem, 1, fp);
    
    SHA256_Final(hash, &sha256);
    
    /* TODO: implement triplicate the config_blob and bl1 image */

    config_blob->bl1_size = bl1_size;
    config_blob->bl1_start = blob_size;
    config_blob->bl1_load_addr = load_addr;
    config_blob->bl1_entry_offset = entry_offset;
    cp_checksum(config_blob->checksum, hash);

    /* generate ecc */
    ptr1 = (unsigned char *)config_blob;
    ptr2 = (unsigned char *)(config_blob->ecc);
    data_size = (unsigned long) ptr2 - (unsigned long) ptr1;
    assert (data_size < sizeof(bl0_blob)); 
    calculate_ecc(ptr1, data_size, ptr2);

    /* write the blob to SRAM */
    fseek(fp, BLOB_ADDR0, SEEK_SET); 
    fwrite((char *) config_blob, sizeof(bl0_blob), 1, fp);

    fclose(fp_read);
    fclose(fp);
}

int main (int argc, char ** argv)
{
    char *fname_sram, *fname_add, *fname_id, *stopstring;
    uint32_t fsize;
    uint64_t load_addr64;
    uint32_t entry_offset;

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
                 sram_file_create(fname_sram, fsize);
                 break;
        case 'a': /* add a file to the image */
                 if (argc != 7) { usage(argv[0]); }
                 fname_sram = argv[2];
                 fname_add = argv[3];
                 fname_id = argv[4];
                 if (argv[6][0] == '0' && argv[6][1] == 'x')
                     entry_offset = (uint32_t) strtoul(argv[6], &stopstring, 16);
                 else 
                     entry_offset = (uint32_t) strtoul(argv[6], &stopstring, 10);
                 if (argv[5][0] == '0' && argv[5][1] == 'x')
                     load_addr64 = strtoul(argv[5], &stopstring, 16);
                 else
                     load_addr64 = strtoul(argv[5], &stopstring, 10);
                 file_add(fname_sram, fname_add, fname_id, load_addr64, entry_offset);
                 break;
        case 'b': /* set up configure_blob */
                 if (argc != 6) { usage(argv[0]); }
                 bl0_blob config_blob;
                 uint32_t entry_offset;
                 fname_sram = argv[2];
                 fname_add = argv[3];
                 if (argv[4][0] == '0' && argv[4][1] == 'x')
                     load_addr64 = strtoul(argv[4], &stopstring, 16);
                 else
                     load_addr64 = strtoul(argv[4], &stopstring, 10);
                 if (argv[5][0] == '0' && argv[5][1] == 'x')
                     entry_offset = strtoul(argv[5], &stopstring, 16);
                 else
                     entry_offset = strtoul(argv[5], &stopstring, 10);
                 cp_blob(&config_blob, fname_sram, fname_add, load_addr64, entry_offset);
                 break;
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
