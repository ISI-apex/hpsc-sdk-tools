BINS =\
    qemu-nand-creator \
    mksfs \
    mkbl0cfg \

all: $(BINS)

.PHONY: all

CFLAGS += -O0 -g

LDFLAGS_ssl = -lssl -lcrypto

qemu-nand-creator: qemu-nand-creator.c

mksfs: mksfs.c ecc.c
mksfs: LDFLAGS+=$(LDFLAGS_ssl)

mkbl0cfg: mkbl0cfg.c ecc.c
mkbl0cfg: LDFLAGS+=$(LDFLAGS_ssl)

$(BINS):
	$(CC) $(CFLAGS) $(INC) $(LIB) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf *.o $(BINS)
