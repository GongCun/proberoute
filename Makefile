OS = $(shell uname -s |tr '[:lower:]' '[:upper:]')
CPPFLAGS += -D_$(OS)
VERSION = 1.0
BINDIR = /usr/local/bin
MANDIR = /usr/local/share/man/man1

ifeq (AIX, $(OS))
include Makefile.aix
else
include Makefile.gcc
endif

OBJS = main.o ProbeAddressInfo.o ProbeException.o ProbePcap.o ProbeSock.o \
options.o

PROGS = proberoute

all: ${PROGS}

proberoute: $(OBJS) 
	${CC} ${CFLAGS} -o $@ $^ $(LIBS)

%.o: %.cpp ProbeRoute.hpp config.h usage.h
	$(CC) $(CPPFLAGS) -c -o $@ $<

usage.h: usage.txt
	@echo 'P("proberoute  version $(VERSION) build on $(OS) at '`date`'");' >$@
	sed <$< >>$@ -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/.*/P("&");/'

install: $(PROGS) $(PROGS).1
	@echo copy $(PROGS) to ${DESTDIR}$(BINDIR)
	@[ -d ${DESTDIR}${BINDIR}/ ] || \
		(umask 022 && mkdir -p ${DESTDIR}${BINDIR}/; \
		chmod 755 ${DESTDIR}${BINDIR}/)
	@install -s -S -f ${DESTDIR}${BINDIR}/ -M 4755 -O root -G system ${PROGS}
	@echo copy $(PROGS).1 to ${DESTDIR}$(MANDIR)
	@[ -d ${DESTDIR}${MANDIR}/ ] || \
		(umask 022 && mkdir -p ${DESTDIR}${MANDIR}/; \
		chmod 755 ${DESTDIR}${MANDIR}/)
	@install -s -f ${DESTDIR}${MANDIR}/ -M 644 -O root -G system ${PROGS}.1

man: $(PROGS)_man.pdf

$(PROGS)_man.pdf: $(PROGS).1
	$(if $(filter AIX,$(OS)),\
	troff -man -Tpsc <$< | psc >$(PROGS).ps,\
	nroff -man -Tps <$< | psc >$(PROGS).ps)
	ps2pdf $(PROGS).ps $@

clean:
	rm -f ${PROGS} *.o core *.BAK *~ usage.h
