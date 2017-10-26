OS = $(shell OS_=`uname -s |tr '[:lower:]' '[:upper:]'` && echo $${OS_%%_*})
##$(info $$OS is [${OS}])
CPPFLAGS += -D_$(OS)
VERSION = 1.0
BINDIR = /usr/local/bin
MANDIR = /usr/local/share/man/man1
LIBDIR = /usr/local/lib
DLLFILE := getmac.dll

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

define install-func
  @echo copy $(PROGS) to ${DESTDIR}$(BINDIR)
  @[ -d ${DESTDIR}${BINDIR}/ ] ||						\
    (umask 022 && mkdir -p ${DESTDIR}${BINDIR}/;				\
    chmod 755 ${DESTDIR}${BINDIR}/)

  @if test $(OS) = AIX; then							\
    install -s -S -f ${DESTDIR}${BINDIR}/ -M 4755 -O root -G system ${PROGS};	\
  elif test $(OS) != CYGWIN; then						\
      install ${PROGS} ${DESTDIR}${BINDIR} && (cd ${DESTDIR}${BINDIR};		\
        strip -s ${PROGS} && chmod 4755 ${PROGS} && chown root ${PROGS});	\
  else										\
      install ${PROGS} ${DESTDIR}${BINDIR} && (cd ${DESTDIR}${BINDIR};		\
        strip -s ${PROGS} && chmod 4755 ${PROGS});				\
      echo copy $(DLLFILE) to ${DESTDIR}${BINDIR};				\
      install ${DLLFILE} ${DESTDIR}${BINDIR} && (cd ${DESTDIR}${BINDIR};	\
        strip -s ${DLLFILE} && chmod 755 ${DLLFILE});				\
  fi

  @echo copy $(PROGS).1 to ${DESTDIR}$(MANDIR)
  @[ -d ${DESTDIR}${MANDIR}/ ] ||						\
    (umask 022 && mkdir -p ${DESTDIR}${MANDIR}/;				\
    chmod 755 ${DESTDIR}${MANDIR}/)

  @if test $(OS) = AIX; then							\
    install -s -f ${DESTDIR}${MANDIR}/ -M 644 -O root -G system ${PROGS}.1;	\
  else										\
    install ${PROGS}.1 ${DESTDIR}${MANDIR} &&					\
    (cd ${DESTDIR}${MANDIR}; chmod 644 ${PROGS}.1);				\
  fi
endef

PROGS = proberoute

all: ${PROGS}

proberoute: $(OBJS) 
	${CC} ${CFLAGS} -D_$(OS) -o $@ $(filter-out %.dll,$^) $(LDFLAGS) $(LIBS)

ifeq (CYGWIN, $(OS))
  # must use C compile mode
  objects = getmac.o getroute.o
  $(objects): %.o: %.c getmac.h
	cc -Wall -g -c -o $@ $<

  getmac.dll: $(objects)
	cc -shared -o $@ $^ -lws2_32
endif

%.o: %.cpp ProbeRoute.hpp config.h usage.h
	$(CC) $(CPPFLAGS) -c -o $@ $<

usage.h: usage.txt
	@echo 'P("proberoute  version $(VERSION) build on $(OS) at '`date`'");' >$@
	sed <$< -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/.*/P("&");/' | tr -d '\r' >>$@ 

install: $(PROGS) $(PROGS).1
	$(install-func)

man: $(PROGS)_man.pdf

$(PROGS)_man.pdf: $(PROGS).1
	$(if $(filter AIX,$(OS)),\
	troff -man -Tpsc <$< | psc >$(PROGS).ps,\
	groff -man -Tps <$< >$(PROGS).ps)
	ps2pdf $(PROGS).ps $@

ifeq (CYGWIN, $(OS))
  # copy the DLL file to build folder
  BUILDDIR := build

  build: $(PROGS)
	@[ -d ${BUILDDIR}/ ] || mkdir -p ${BUILDDIR}/
	@cygcheck $(PROGS) | sed '1d' | grep -e cygwin -e pcap -e packet | sed 's/\\/\\\\/g' | \
	while read f; do cp -p $$f ${BUILDDIR}/; done
	cp -p $(PROGS) ${BUILDDIR}/ && strip -s ${BUILDDIR}/$(PROGS)
endif

clean:
	rm -f ${PROGS} ${PROGS}.exe *.o *.dll core *.BAK *~ usage.h
