
all: qemu-nand-creator sram-image-utils

.PHONY: all

CFLAGS += -O2 -g

qemu-nand-creator: qemu-nand-creator.c
	$(CC) $(CFLAGS) -o $@ $^

sram-image-utils: sram-image-utils.c ecc.c
	$(CC) $(CFLAGS) $(INC) $(LIB) -o $@ $^ -lssl -lcrypto

clean:
	rm -rf *.o qemu-nand-creator sram-image-utils
