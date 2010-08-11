# Generated automatically from Makefile.in by configure.
# $Id: Makefile.in,v 1.5 2003/06/22 22:59:45 ek Exp $
LIBSRC=     pam_sqlite3.c
LIBOBJ=     pam_sqlite3.o pam_get_pass.o pam_std_option.o pam_get_service.o
LIBLIB=     pam_sqlite3.so

DISTDIR=    pam_sqlite3-0.1
ROOTDIR=	

LINK=		-L/usr/lib
LDLIBS=		${LINK} -lcrypt -lpam  -lcrypt -lsqlite3 -lpam_misc
INCLUDE=	-I/usr/include
CFLAGS=		 -fPIC -DPIC -Wall -D_GNU_SOURCE ${INCLUDE}


all: ${LIBLIB}

DISTDIRS=	debian
DISTFILES= acconfig.h README pam_get_pass.c pam_get_service.c pam_mod_misc.h \
	pam_sqlite3.c pam_std_option.c test.c debian/changelog debian/control \
	debian/copyright debian/dirs debian/rules Makefile.in configure.in \
	config.h.in install-sh config.sub config.guess install-module configure \
	CREDITS

distfiles: ${DISTFILES}

${DISTDIR}.tar.gz: distfiles
	mkdir -p ${DISTDIR}
	for d in ${DISTDIRS}; do \
		mkdir -p ${DISTDIR}/$$d; \
	done
	for f in ${DISTFILES}; do \
		cp -pR $$f ${DISTDIR}/$$f; \
	done
	tar -czvvf ${DISTDIR}.tar.gz ${DISTDIR}
	rm -rf ${DISTDIR}

dist: ${DISTDIR}.tar.gz

${LIBLIB}: ${LIBOBJ}
	${CC} ${CFLAGS} ${INCLUDE} -shared -o $@ ${LIBOBJ} ${LDLIBS} 

test: test.c
	${CC} ${CFLAGS} -o $@ test.c ${LDLIBS}

install:
	@(ROOTDIR=${ROOTDIR}; ./install-module linux-gnu)

clean:
	rm -f ${LIBOBJ} ${LIBLIB} core test *~ 
	rm -f ${DISTDIR}.tar.gz

dist-clean: distclean
distclean: clean
	rm -f config.cache config.log config.status config.h
	rm -f Makefile

extraclean: clean
	rm -f *.a *.o *.so *.bak 
