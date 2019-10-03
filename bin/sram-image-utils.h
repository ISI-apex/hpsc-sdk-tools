
#ifndef H_SRAM_UTILS
#define H_SRAM_UTILS

#define FILE_NAME_LENGTH 200
typedef struct {
    uint32_t valid;
    uint32_t offset;	/* offset in SRAM image */
    uint32_t size;
    uint32_t load_addr;		/* 32bit load address in DRAM at run-time */
    uint32_t load_addr_high;	/* high 32bit of 64 bit load address in DRAM at run-time */
    char  name[FILE_NAME_LENGTH];
    uint32_t entry_offset;      /* the offset of the entry point in the image */
    uint8_t checksum[32];          /* SHA-256 checksum */
    uint8_t ecc[ECC_512_SIZE];                /* ecc of the struct */
} file_descriptor;

typedef struct {
    uint32_t low_mark_data;	/* low mark of data */
    uint32_t high_mark_fd;	/* high mark of file descriptors */
    uint32_t n_files;		/* number of files */
    uint32_t fsize;		/* sram file size */
    uint8_t ecc[ECC_512_SIZE];                /* ecc of the struct */
} global_table;
#endif
