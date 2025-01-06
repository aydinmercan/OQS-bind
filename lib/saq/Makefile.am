include $(top_srcdir)/Makefile.top

lib_LTLIBRARIES = libsaq.la

libsaq_ladir = $(includedir)/saq
libsaq_la_HEADERS =			\
	include/saq/merkleauthpath.h	\
	include/saq/merklecommon.h	\
	include/saq/merklenode.h	\
	include/saq/merklestream.h

libsaq_la_SOURCES =			\
	$(libsaq_la_HEADERS)		\
	merkleauthpath.c		\
	merklecommon.c			\
	merklenode.c			\
	merklestream.c

libsaq_la_CPPFLAGS =			\
	$(AM_CPPFLAGS)			\
	$(LIBSAQ_CFLAGS)

libsaq_la_LDFLAGS =		\
	$(AM_LDFLAGS)		\
	-release "$(PACKAGE_VERSION)"
