OS = $(shell OS_=`uname -s |tr '[:lower:]' '[:upper:]'` && echo $${OS_%%_*})
##$(info $$OS is [${OS}])
CPPFLAGS += -D_$(OS)
VERSION = 1.0
BINDIR = /usr/local/bin
MANDIR = /usr/local/share/man/man1

ifeq (AIX, $(OS))
include Makefile.aix
else ifeq (CYGWIN, $(OS))
include Makefile.cygwin
else
include Makefile.gcc
endif

OBJS = main.o ProbeAddressInfo.o ProbeException.o ProbePcap.o ProbeSock.o \
options.o

ifeq (CYGWIN, $(OS))
OBJS += getmac.dll
override LIBS += -lgetmac
override LDFLAGS += -L.
endif

PROGS = proberoute

all: ${PROGS}

proberoute: $(OBJS) 
	${CC} ${CFLAGS} -D_$(OS) -o $@ $(filter-out %.dll,$^) $(LDFLAGS) $(LIBS)

ifeq (CYGWIN, $(OS))
  # must use C compile mode
  getmac.dll: getmac.c
	cc -Wall -g -c -o getmac.o $<
	cc -shared -o $@ getmac.o -lws2_32
endif

%.o: %.cpp ProbeRoute.hpp config.h usage.h
	$(CC) $(CPPFLAGS) -c -o $@ $<

usage.h: usage.txt
	@echo 'P("proberoute  version $(VERSION) build on $(OS) at '`date`'");' >$@
	sed <$< -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/.*/P("&");/' | tr -d '\r' >>$@ 

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
	groff -man -Tps <$< >$(PROGS).ps)
	ps2pdf $(PROGS).ps $@

clean:
	rm -f ${PROGS} ${PROGS}.exe *.o *.dll core *.BAK *~ usage.h
