
AM_CFLAGS = \
	$(GLOBAL_CFLAGS) \
	$(LFS_CFLAGS) \
	$(libirecovery_CFLAGS) \
	$(libimobiledevice_CFLAGS) \
	$(libusbmuxd_CFLAGS) \
	$(libplist_CFLAGS) \
	$(limd_glue_CFLAGS) \
	$(libtatsu_CFLAGS) \
	$(libzip_CFLAGS) \
	$(zlib_CFLAGS) \
	$(libcurl_CFLAGS)

AM_LDFLAGS = \
	$(AC_LDFLAGS) \
	$(libirecovery_LIBS) \
	$(libimobiledevice_LIBS) \
	$(libusbmuxd_LIBS) \
	$(libplist_LIBS) \
	$(limd_glue_LIBS) \
	$(libtatsu_LIBS) \
	$(libzip_LIBS) \
	$(zlib_LIBS) \
	$(libcurl_LIBS)

AM_LDADD = $(AC_LDADD)

bin_PROGRAMS = idevicerestore

idevicerestore_SOURCES = \
	idevicerestore.c idevicerestore.h \
	log.c log.h \
	endianness.h \
	common.c common.h \
	fls.c fls.h \
	mbn.c mbn.h \
	img3.c img3.h \
	img4.c img4.h \
	ftab.c ftab.h \
	ipsw.c ipsw.h \
	normal.c normal.h \
	dfu.c dfu.h \
	recovery.c recovery.h \
	restore.c restore.h \
	asr.c asr.h \
	fdr.c fdr.h \
	ace3.c ace3.h \
	download.c download.h \
	locking.c locking.h

idevicerestore_CFLAGS = $(AM_CFLAGS)
idevicerestore_LDFLAGS = $(AM_LDFLAGS)
idevicerestore_LDADD = $(AM_LDADD)
if HAVE_TURDUS_MERULA
idevicerestore_SOURCES += \
	turdus/merula.c turdus/merula.h
idevicerestore_CFLAGS += -DHAVE_TURDUS_MERULA $(libDER_CFLAGS) $(libfragmentzip_CFLAGS)
idevicerestore_LDFLAGS += $(libfragmentzip_LIBS)
endif
if HAVE_LIBHFSPLUS
idevicerestore_SOURCES += \
	libhfsplus/asr_patch.c libhfsplus/asr_patch.h libhfsplus/hfs_patch_asr.h \
	libhfsplus/common/abstractfile.c libhfsplus/common/abstractfile.h libhfsplus/common/libhfsplus-common.h \
	libhfsplus/hfs/btree.c libhfsplus/hfs/catalog.c libhfsplus/hfs/extents.c libhfsplus/hfs/fastunicodecompare.c \
	libhfsplus/hfs/flatfile.c libhfsplus/hfs/hfs.c libhfsplus/hfs/hfscompress.c libhfsplus/hfs/hfscompress.h libhfsplus/hfs/hfslib.c \
	libhfsplus/hfs/hfslib.h libhfsplus/hfs/hfsplus.h libhfsplus/hfs/rawfile.c libhfsplus/hfs/utility.c libhfsplus/hfs/volume.c libhfsplus/hfs/xattr.c
endif
