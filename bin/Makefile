BINS =\
    qemu-nand-creator \
    mksfs \
    mkbl0cfg \

all: $(BINS)

.PHONY: all

CFLAGS += -O0 -g

PKG_ssl=openssl
LDFLAGS_ssl = $(shell pkg-config --libs $(PKG_ssl))
CFLAGS_ssl = $(shell pkg-config --cflags $(PKG_ssl))

qemu-nand-creator: qemu-nand-creator.c

mksfs: mksfs.c ecc.c
mksfs: LDFLAGS+=$(LDFLAGS_ssl)
mksfs: CFLAGS+=$(CFLAGS_ssl)

mkbl0cfg: mkbl0cfg.c ecc.c
mkbl0cfg: LDFLAGS+=$(LDFLAGS_ssl)
mkbl0cfg: CFLAGS+=$(CFLAGS_ssl)

$(BINS):
	$(CC) $(CFLAGS) $(INC) $(LIB) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf *.o $(BINS)
