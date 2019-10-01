# Recipes to create a sysroot with dependencies of the HPSC SDK
#
# Only needed if system (the OS distribution) cannot provide up-to-date
# versions of these dependencies, as may happen when working without root
# privileges. Often, a system may provide the library binary, but not its
# development headers, which are needed to build against that library.
#
# These recipes provides the same functionality as the Poky SDK installer
# could/should (once it is complete) -- with the difference of context: not for
# distributing the SDK but for building and using the SDK from its source tree.
#
# Another difference, which is a corrolary of the above difference in usage
# context: Poky's sysroot is exhaustive (it eliminates absolutely all
# dependencies on any system libraries), while this Makefile's sysroot does
# depend on at least some system libraries and binaries. This is indended,
# because when developing the SDK, we want to run it on the system, and the
# only reason we provide a sysroot is only for the case when something prevents
# the developer from installing the dependencie into the system (e.g. no root,
# and/or system-provided packages are out-of-date and no updates are
# available).

all: tools libs py env

BLD=bld

# Actual sysroot will be created here
SYSROOT=$(BLD)/sysroot

FETCH=$(BLD)/fetch
FETCH_CACHE?=$(FETCH)
WORK=$(BLD)/work
PATCHES=patch

PREFIX=$(SYSROOT)/usr
HPREFIX=$(abspath $(PREFIX))

BIN=$(PREFIX)/bin
INC=$(PREFIX)/include
PC=$(PREFIX)/lib/pkgconfig
PC64=$(PREFIX)/lib64/pkgconfig

# Tools required for building the SDK:
# ... provided by the system
WGET=wget
TAR=tar
PATCH=patch
# ... optional (not currently used by anything)
UNZIP=unzip
# ... built while building the SDK (must be absolute paths, not via $(BIN))
FAKEROOT=$(HPREFIX)/bin/fakeroot
PYTHON=$(HPREFIX)/bin/python3
PKGCONFIG=$(HPREFIX)/bin/pkg-config

PYTHON_SITE_REL=$(PREFIX)/lib/python$(VER_MAJMIN_python)/site-packages
PYTHON_SITE=$(abspath $(PYTHON_SITE_REL))

define ENV
# Auto-generated SDK environment file
HPREFIX=$(abspath $(SYSROOT))/usr
export PATH=$$HPREFIX/sbin:$$HPREFIX/bin:$$PATH
export PYTHONPATH=$(PYTHON_SITE):$$PYTHONPATH
export LD_LIBRARY_PATH=$$HPREFIX/lib64:$$HPREFIX/lib
export PKG_CONFIG_PATH=$$HPREFIX/lib64/pkgconfig:$$HPREFIX/lib/pkgconfig
endef

ENV_FILE=$(BLD)/env.sh
env: $(ENV_FILE)
$(ENV_FILE): export ENV_SH=$(ENV)
$(ENV_FILE):
	echo "$$ENV_SH" > $@
env/clean:
	rm -f $(ENV_FILE)
.PHONY: env env/clean

# Note: the identifiers need to be unique across this whole file, including
# across separate categories, but the tarballs and build directories may have
# the same name as long as they are in different categories.

# Reason for dependency in recorded in target definitions
DEPS_LIB=\
	attr \
	libcap \
	util_linux \
	pcre \
	libffi \
	glib \
	pixman \
	libxfs \
	sqlite \
	ncurses \
	openssl \
	curl \

# Tools
#
# fakeroot: for building some deps here, and for initramfs building
# dtc: for non-nested device tree builds (nested repos usually provide dtc)
# screen: for connecting to serial ports
# git: for work with repos (optional)
# ninja: needed by meson, which is needed to build glib
#
DEPS_TOOL=\
	fakeroot \
	dtc \
	screen \
	git \
	python \
	python2 \
	texinfo \
	uboottools \
	make \
	ninja \
	pkgconfig \
	patchelf \
	rsync \
	re2c \

# Python packages
#
# setuptools: for installing any other python packages
# configparser: for manipulating INI config files
# argparse: CLI in various tools
# pprint: JSON formatting used in some tools
# meson: needed to build glib
#
DEPS_PY=\
	setuptools \
	setuptools_scm \
	argparse \
	configparser \
	pprint \
	meson \

DEPS_NATIVE=$(DEPS_LIB) $(DEPS_TOOL)
DEPS=$(DEPS_NATIVE) $(DEPS_PY)

# Extract first character from string (identifier), for Python URLs
LETTERS=a b c d e f g h i j k l m n o p q r s t u v w x y z \
        A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
firstletter=$(strip $(foreach let,$(LETTERS),$(if $(filter $(let)%,$(1)),$(let))))

# Components: note that there are default values, see end of this list

# Constraints on versions: support GCC >= 4.8

VER_attr=2.4.48
URL_attr=http://download.savannah.nongnu.org/releases/attr
ART_attr=$(PC)/libattr.pc

VER_libcap=2.25
URL_libcap=http://ftp.debian.org/debian/pool/main/libc/libcap2
TARBALL_libcap=libcap2_$(VER_libcap).orig.tar.xz
ART_libcap=$(PC64)/libcap.pc

VER_fakeroot=1.24
URL_fakeroot=http://deb.debian.org/debian/pool/main/f/fakeroot
TARBALL_fakeroot=fakeroot_$(VER_fakeroot).orig.tar.gz
ART_fakeroot=$(BIN)/fakeroot

VER_MAJMIN_util_linux=2.34
#VER_PATCH_util_linux=
#VER_util_linux=$(VER_MAJMIN_util_linux).$(VER_PATCH_util_linux)
VER_util_linux=$(VER_MAJMIN_util_linux)
URL_util_linux=https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v$(VER_MAJMIN_util_linux)
TARBALL_util_linux=util-linux-$(VER_util_linux).tar.xz
DIR_util_linux=util-linux-$(VER_util_linux)
ART_util_linux=$(PC)/mount.pc

VER_pcre=8.43
URL_pcre=https://ftp.pcre.org/pub/pcre
TARBALL_pcre=pcre-$(VER_pcre).tar.bz2
ART_pcre=$(PC)/libpcre.pc

VER_libffi=3.2.1
URL_libffi=ftp://sourceware.org/pub/libffi
ART_libffi=$(PC)/libffi.pc

VER_MAJMIN_glib=2.62
VER_PATCH_glib=0
VER_glib=$(VER_MAJMIN_glib).$(VER_PATCH_glib)
TARBALL_glib=glib-$(VER_glib).tar.xz
URL_glib=http://ftp.gnome.org/pub/gnome/sources/glib/$(VER_MAJMIN_glib)
ART_glib=$(PC)/glib-2.0.pc

VER_pixman=0.38.4
URL_pixman=https://www.cairographics.org/releases
ART_pixman=$(PC)/pixman-1.pc

VER_libxfs=4.20.0
URL_libxfs=https://mirrors.edge.kernel.org/pub/linux/utils/fs/xfs/xfsprogs
TARBALL_libxfs=xfsprogs-$(VER_libxfs).tar.xz
DIR_libxfs=xfsprogs-$(VER_libxfs)
ART_libxfs=$(INC)/xfs/xfs.h

VER_sqlite=3.29.0
URL_sqlite=https://www.sqlite.org/2019
VER_sqlite_NUM=3290000
TARBALL_sqlite=sqlite-autoconf-$(VER_sqlite_NUM).tar.gz
DIR_sqlite=sqlite-autoconf-$(VER_sqlite_NUM)
ART_sqlite=$(PC)/sqlite3.pc

VER_dtc=1.5.1
URL_dtc=https://git.kernel.org/pub/scm/utils/dtc/dtc.git/snapshot
ART_dtc=$(BIN)/dtc

VER_ncurses=6.1
URL_ncurses=https://invisible-mirror.net/archives/ncurses
ART_ncurses=$(PC)/ncurses.pc

VER_openssl=1.1.1d
URL_openssl=https://www.openssl.org/source
ART_openssl=$(PC64)/openssl.pc

VER_curl=7.66.0
URL_curl=https://curl.haxx.se/download
ART_curl=$(PC)/libcurl.pc

VER_screen=4.6.2
URL_screen=https://ftp.gnu.org/gnu/screen
ART_screen=$(BIN)/screen

VER_git=2.23.0
URL_git=https://mirrors.edge.kernel.org/pub/software/scm/git
TARBALL_git=git-$(VER_git).tar.xz
ART_git=$(BIN)/git

VER_MAJMIN_python=3.7
VER_PATCH_python=4
VER_python=$(VER_MAJMIN_python).$(VER_PATCH_python)
URL_python=https://www.python.org/ftp/python/$(VER_python)
TARBALL_python=Python-$(VER_python).tar.xz
DIR_python=Python-$(VER_python)
ART_python=$(BIN)/python3

# Python2 is needed by Yocto build (see HOSTTOOLS) and Qemu build
VER_python2=2.7.16
URL_python2=https://www.python.org/ftp/python/$(VER_python2)
TARBALL_python2=Python-$(VER_python2).tar.xz
DIR_python2=Python-$(VER_python2)
ART_python2=$(BIN)/python2

VER_texinfo=6.7
URL_texinfo=https://ftp.gnu.org/gnu/texinfo
ART_texinfo=$(BIN)/makeinfo

# u-boot >=2018.05 requires GCC >= 6 (but 2018.05 breaks, so we patch 2019.x)
VER_uboottools=2019.07
# Option A: Gitlab
#VER_HASH_uboottools=<insert commit hash of release here>
#URL_uboottools=https://gitlab.denx.de/u-boot/u-boot/-/archive/v$(VER_uboottools)
#DIR_uboottools=u-boot-v$(VER_uboottools)-$(VER_HASH_uboottools)
# Option B: FTP server
URL_uboottools=ftp://ftp.denx.de/pub/u-boot
DIR_uboottools=u-boot-$(VER_uboottools)

TARBALL_uboottools=u-boot-$(VER_uboottools).tar.bz2
ART_uboottools=$(BIN)/mkimage

# SSW makefile requires make >= 3.81
VER_make=4.2.1
URL_make=https://ftp.gnu.org/gnu/make
ART_make=$(BIN)/make

VER_pkgconfig=0.29.2
URL_pkgconfig=https://pkg-config.freedesktop.org/releases
TARBALL_pkgconfig=pkg-config-$(VER_pkgconfig).tar.gz
DIR_pkgconfig=pkg-config-$(VER_pkgconfig)
ART_pkgconfig=$(BIN)/pkg-config

VER_patchelf=0.10
URL_patchelf=https://nixos.org/releases/patchelf/patchelf-$(VER_patchelf)
ART_patchelf=$(BIN)/patchelf

VER_rsync=3.1.3
URL_rsync=https://download.samba.org/pub/rsync
ART_rsync=$(BIN)/rsync

# required by ninja
VER_re2c=1.2.1
URL_re2c=https://github.com/skvadrik/re2c/releases/download/1.2.1
TARBALL_re2c=re2c-$(VER_re2c).tar.xz
ART_re2c=$(BIN)/re2c

# required by meson, which is required by glib
VER_ninja=1.9.0
URL_ninja=https://github.com/ninja-build/ninja/archive
TARBALL_ninja=v$(VER_ninja).tar.gz
ART_ninja=$(BIN)/ninja

# Python packages

# pypi distributes setuptools only in .zip package, so use GitHub
VER_setuptools=41.2.0
VER_POST_setuptools=post20191001
URL_setuptools=https://github.com/pypa/setuptools/archive
TARBALL_setuptools=v$(VER_setuptools).tar.gz
ART_VER_setuptools=$(VER_setuptools).$(VER_POST_setuptools)

VER_setuptools_scm=3.3.3
VER_argparse=1.4.0
VER_pprint=0.1
VER_configparser=4.0.2
VER_meson=0.51.2

# Defaults for url fname, tarballs and dirs, override the exceptions above
$(foreach d,$(DEPS),$(eval TARBALL_$(d)?=$(d)-$(VER_$(d)).tar.gz))
$(foreach d,$(DEPS),$(eval FNAME_$(d)?=$(TARBALL_$(d))))
$(foreach d,$(DEPS),$(eval DIR_$(d)?=$(d)-$(VER_$(d))))

# Default URL for python packages for downloading from PyPI, but should there
# be any exceptions, simply define their respective URL vars below.
$(foreach p,$(DEPS_PY),\
	$(eval URL_$(p)?=https://pypi.io/packages/source/$(call firstletter,$(p))/$(p)))

# Default for artifacts for python packages artifacts, override the exceptions above
$(foreach p,$(DEPS_PY),\
	$(eval ART_VER_$(p)?=$(VER_$(p)))\
	$(eval ART_$(p)?=$(PYTHON_SITE_REL)/$(p)-$(ART_VER_$(p))-py$(VER_MAJMIN_python).egg))

libs: $(DEPS_LIB)
tools: $(DEPS_TOOL)
py: $(DEPS_PY)
py/clean: $(foreach d,$(DEPS_PY),$(d)/clean)

fetch: $(foreach d,$(DEPS),$(FETCH)/$(TARBALL_$(d)))

# Ideally, this would be "%/:" but make <=3.81 eats trailing slashes
%/. :
	mkdir -p $@

# don't clean fetched tarballs unless explicitly requested
clean: sysroot/clean env/clean bld/clean
.PHONY: clean

sysroot/clean:
	rm -rf $(SYSROOT)/
.PHONY: sysroot/clean

bld/clean:
	rm -rf $(WORK)/
bld/%/clean:
	rm -f $(WORK)/$(DIR_$*)
fetch/clean:
	rm -rf $(FETCH)/
fetch/%/clean:
	rm -f $(FETCH)/$(TARBALL_$*)
.PHONY: bld/clean bld/%/clean fetch/clean fetch/%/clean

define fetch-rule
fetch: $(FETCH)/$(TARBALL_$(1))
$(FETCH_CACHE)/$(TARBALL_$(1)): | $(FETCH_CACHE)/.
	$(WGET) --no-verbose -O $$@ $(URL_$(1))/$(FNAME_$(1))
.INTERMEDIATE: $(FETCH_CACHE)/$(TARBALL_$(1))
.SECONDARY: $(FETCH_CACHE)/$(TARBALL_$(1))
endef

# We make a copy, so that we're self-sufficient in case FETCH_CACHE goes away
ifneq ($(patsubst %.,%,$(FETCH)),$(FETCH_CACHE)) # strip . from /. (see mkdir rule)
# This mkdir rule is so that $(FETCH)/% doesn't match $(FETCH)/. and create
# a circular dependency. This is only needed with the /. workaround (see mkdir rule)
$(FETCH)/.:
	mkdir -p $@
$(FETCH)/%: $(FETCH_CACHE)/% | $(FETCH)/.
	cp $< $@
endif
.SECONDARY: $(FETCH)/.

# touch the directory, since the timestamp of the dir in tar may be stored and
# it will be older than the tarball, which would cause the target to be remade.
define extract-rule-tar
$(3)/$(DIR_$(1)): $(2)/$(TARBALL_$(1)) | $(3)/.
	$(TAR) -C $(3) -x -f $$<
	@[ -d "$$@" ] || (echo "ERROR: $$@ not a dir: wrong DIR_$(1)?" 2>&1 && exit 1)
	touch $$@
endef

define extract-rule-zip
$(3)/$(DIR_$(1)): $(2)/$(TARBALL_$(1)) | $(3)/.
	cd $(3) && $(UNZIP) -o -q $(abspath $$<)
endef

define clean-rule
$(1)/clean:
	rm -rf $(WORK)/$(DIR_$(1)) $(ART_$(1))
endef

$(foreach d,$(DEPS),\
	$(eval $(call fetch-rule,$(d)))\
	$(eval $(call clean-rule,$(d))))

DEPS_TAR=$(foreach d,$(DEPS),\
	$(if $(filter %.tar.gz %.tar.xz %.tar.bz2 %.tar,$(TARBALL_$(d))),$(d),))
DEPS_ZIP=$(foreach d,$(DEPS),\
	$(if $(filter %.zip,$(TARBALL_$(d))),$(d),))

$(foreach d,$(filter $(DEPS),$(DEPS_TAR)),\
	$(eval $(call extract-rule-tar,$(d),$(FETCH),$(WORK))))
$(foreach d,$(filter $(DEPS),$(DEPS_ZIP)),\
	$(eval $(call extract-rule-zip,$(d),$(FETCH),$(WORK))))

# Make extract target a prereq of build/install target
$(foreach d,$(DEPS),$(eval $(ART_$(d)): | $(WORK)/$(DIR_$(d))))

# Alias for each dependency, that points to the artifact
$(foreach d,$(DEPS),$(eval $(d): $(ART_$(d))))

# Define per-target DIR to allow recipies to be more concise
$(foreach d,$(DEPS),$(eval $(ART_$(d)): DIR=$(WORK)/$(DIR_$(d))))

PKGCFG_PATHS=$(HPREFIX)/lib64/pkgconfig:$(HPREFIX)/lib/pkgconfig

# Env vars usually respected by autoconf configure script
SYSROOT_VARS=\
	PKG_CONFIG_PATH=$(PKGCFG_PATHS) \
	LD_LIBRARY_PATH=$(HPREFIX)/lib64:$(HPREFIX)/lib \
	CFLAGS+=-I$(HPREFIX)/include \
	LDFLAGS+="-L$(HPREFIX)/lib64 -L$(HPREFIX)/lib -Wl,-rpath=$(HPREFIX)/lib64 -Wl,-rpath=$(HPREFIX)/lib" \
	PATH="$(HPREFIX)/bin:$$PATH" \

$(ART_pkgconfig):
	cd $(DIR) && $(SYSROOT_VARS) ./configure --prefix=$(HPREFIX)
	$(MAKE) -C $(DIR) install

# Most targets can reuse this standard autotools recipe
$(ART_attr) \
$(ART_fakeroot) \
$(ART_libffi) \
$(ART_pcre) \
$(ART_pixman) \
$(ART_sqlite) \
$(ART_ncurses) \
$(ART_screen) \
$(ART_curl) \
$(ART_texinfo) \
$(ART_git) \
$(ART_patchelf) \
$(ART_rsync) \
$(ART_re2c) \
: | $(ART_pkgconfig)
	cd $(DIR) && $(SYSROOT_VARS) ./configure --prefix=$(HPREFIX) $(CONFIG_FLAGS)
	$(MAKE) -C $(DIR)
	$(MAKE) -C $(DIR) install

$(ART_glib): | $(ART_pkgconfig) $(ART_python) $(ART_libffi) $(ART_pcre) $(ART_util_linux)
	cd $(DIR) && $(SYSROOT_VARS) meson --prefix=$(HPREFIX) \
		--pkg-config-path $(PKGCFG_PATHS) _build
	cd $(DIR) && ninja -C _build
	cd $(DIR) && ninja -C _build install

$(ART_libcap): | $(ART_pkgconfig) $(ART_attr)
	$(PATCH) -d $(DIR) -p1 < $(wildcard $(PATCHES)/libcap/*.patch)
	$(MAKE) -C $(DIR) DESTDIR=$(abspath $(SYSROOT)) LDFLAGS+=-L$(HPREFIX)/lib \
		RAISE_SETFCAP=no install \

$(ART_fakeroot): | $(ART_libcap)

$(ART_util_linux): | $(ART_pkgconfig) $(ART_fakeroot)
	cd $(DIR) && $(SYSROOT_VARS) ./configure --prefix=$(HPREFIX) \
			--with-bashcompletiondir=$(HPREFIX)/share/bash-completions \
			--without-python
	$(MAKE) -C $(DIR)
	$(FAKEROOT) $(MAKE) -C $(DIR) install

$(ART_pcre): | $(ART_pkgconfig)
$(ART_pcre): CONFIG_FLAGS=--enable-utf --enable-unicode-properties

$(ART_libxfs): | $(ART_util_linux)
	cd $(DIR) && $(SYSROOT_VARS) ./configure --prefix=$(HPREFIX)
	$(MAKE) -C $(DIR)
	$(MAKE) -C $(DIR) install-dev

$(ART_ncurses): CONFIG_FLAGS=--with-pkg-config-libdir=$(HPREFIX)/lib/pkgconfig \
			     --enable-pc-files --with-shared --without-ada

$(ART_openssl): | $(ART_ncurses)
	cd $(DIR) && $(SYSROOT_VARS) ./config --prefix=$(HPREFIX)
	$(MAKE) -C $(DIR)
	$(MAKE) -C $(DIR) install

$(ART_dtc): | $(ART_pkgconfig)
	$(MAKE) -C $(DIR) NO_PYTHON=1 PREFIX=$(HPREFIX) install

$(ART_screen): | $(ART_ncurses)
$(ART_curl): | $(ART_openssl)

$(ART_make):
	$(PATCH) -d $(DIR) -p1 < $(wildcard $(PATCHES)/make/*.patch)
	cd $(DIR) && $(SYSROOT_VARS) ./configure --prefix=$(HPREFIX) $(CONFIG_FLAGS)
	$(MAKE) -C $(DIR)
	$(MAKE) -C $(DIR) install

$(ART_git): | $(ART_curl)
$(ART_git): CONFIG_FLAGS=--with-curl

PY_PKGCFG_DEPS=ncurses libffi
$(ART_python): CONFIG_FLAGS=--enable-loadable-sqlite-extensions
$(ART_python) $(ART_python2): | $(ART_sqlite) $(ART_openssl) $(ART_ncurses) $(ART_libffi)
	cd $(DIR) && $(SYSROOT_VARS) && \
		CFLAGS+="$$(PKG_CONFIG_PATH=$(PKGCFG_PATHS) \
						$(PKGCONFIG) --cflags $(PY_PKGCFG_DEPS))" \
		CPPFLAGS+="$$CFLAGS" \
		LDFLAGS+="$$(PKG_CONFIG_PATH=$(PKGCFG_PATHS) \
						$(PKGCONFIG) --libs $(PY_PKGCFG_DEPS))" \
		./configure --prefix=$(HPREFIX) $(CONFIG_FLAGS) --enable-optimizations
	$(MAKE) -C $(DIR) build_all
	$(MAKE) -C $(DIR) install

UBOOTTOOLS_VARS=HOST_EXTRACFLAGS="-I$(HPREFIX)/include"
$(ART_uboottools): | $(ART_pkgconfig)
	$(PATCH) -d $(DIR) -p1 < $(wildcard $(PATCHES)/uboottools/*.patch)
	cd $(DIR) && $(SYSROOT_VARS) $(UBOOTTOOLS_VARS) $(MAKE) defconfig
	cd $(DIR) && $(SYSROOT_VARS) $(UBOOTTOOLS_VARS) $(MAKE) tools envtools
	cd $(DIR) && install -m 755 -t "$(HPREFIX)/bin" \
		tools/{mk{,env}image,env/fw_printenv,img2srec,dumpimage,netconsole,jtagconsole,ncb}
	cd $(DIR) && ln -sf fw_printenv $(HPREFIX)/bin/fw_setenv

$(ART_ninja): $(ART_re2c) $(ART_python)
	cd $(DIR) && $(SYSROOT_VARS) PYTHONPATH=$(PYTHON_SITE):$(PYTHONPATH) \
		$(PYTHON) configure.py --bootstrap
	install -m755 -D $(DIR)/ninja	"$(HPREFIX)/bin/ninja"

$(ART_meson): $(ART_ninja)
$(ART_configparser): $(ART_setuptools_scm)

DEPS_PY_PKGS=$(filter-out setuptools,$(DEPS_PY))
PY_ARTS=$(foreach d,$(DEPS_PY),$(ART_$(d)))
PY_ARTS_PKGS=$(foreach d,$(DEPS_PY_PKGS),$(ART_$(d)))
$(ART_setuptools): $(ART_python)
	cd $(DIR) && PYTHONPATH=$(PYTHON_SITE):$(PYTHONPATH) \
		$(PYTHON) bootstrap.py && \
		$(PYTHON) setup.py install --prefix=$(HPREFIX)
$(PY_ARTS_PKGS): $(ART_python)
	cd $(DIR) && PYTHONPATH=$(PYTHON_SITE):$(PYTHONPATH) \
		$(PYTHON) setup.py install --prefix=$(HPREFIX)

# All python packages depend on setuptools
$(foreach d,$(DEPS_PY_PKGS),$(eval $(ART_$(d)): $(ART_setuptools)))
