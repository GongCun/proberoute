OS = $(shell OS_=`uname -s |tr '[:lower:]' '[:upper:]'` && echo $${OS_%%_*})
##$(info $$OS is [${OS}])
CPPFLAGS += -D_$(OS)
VERSION = 1.0
BINDIR = /usr/local/bin
MANDIR = /usr/local/share/man/man1
LIBDIR = /usr/local/lib
DLLFILE := winsock.dll Packet.dll wpcap.dll
INSTALL := /usr/bin/install

# export PATH := .:$(PATH)

ifeq (AIX, $(OS))
include Makefile.aix
else ifeq (CYGWIN, $(OS))
include Makefile.cygwin
else
include Makefile.gcc
endif

PROGS = proberoute

all: ${PROGS}

OBJS = main.o ProbeAddressInfo.o ProbeException.o ProbePcap.o ProbeSock.o \
options.o

ifeq (CYGWIN, $(OS))
OBJS += ${DLLFILE} listNdisWanAdapter.o
override LIBS += -lwinsock
override LDFLAGS += -L.
listNdisWanAdapter.o: listNdisWanAdapter.c
	cc -g -Wall -DHAVE_REMOTE -c -o $@ $<
endif

define install-func
  @echo copy $(PROGS) to ${DESTDIR}$(BINDIR)
  @[ -d ${DESTDIR}${BINDIR}/ ] ||						\
    (umask 022 && mkdir -p ${DESTDIR}${BINDIR}/;				\
    chmod 755 ${DESTDIR}${BINDIR}/)

  @if test $(OS) = AIX; then							\
    $(INSTALL) -s -S -f ${DESTDIR}${BINDIR}/ -M 4755 -O root -G system ${PROGS};	\
  elif test $(OS) != CYGWIN; then						\
      $(INSTALL) ${PROGS} ${DESTDIR}${BINDIR} && (cd ${DESTDIR}${BINDIR};		\
        strip ${PROGS} && chmod 4755 ${PROGS} && chown root ${PROGS});		\
  else										\
      $(INSTALL) ${PROGS} ${DESTDIR}${BINDIR} && (cd ${DESTDIR}${BINDIR};		\
        strip ${PROGS} && chmod 4755 ${PROGS});					\
      echo copy $(DLLFILE) to ${DESTDIR}${BINDIR};				\
      cp -p ${DLLFILE} ${DESTDIR}${BINDIR} && (cd ${DESTDIR}${BINDIR};	\
        strip ${DLLFILE} && chmod 755 ${DLLFILE});				\
  fi

  @echo copy $(PROGS).1 to ${DESTDIR}$(MANDIR)
  @[ -d ${DESTDIR}${MANDIR}/ ] ||						\
    (umask 022 && mkdir -p ${DESTDIR}${MANDIR}/;				\
    chmod 755 ${DESTDIR}${MANDIR}/)

  @if test $(OS) = AIX; then							\
    $(INSTALL) -s -f ${DESTDIR}${MANDIR}/ -M 644 -O root -G system ${PROGS}.1;	\
  else										\
    $(INSTALL) ${PROGS}.1 ${DESTDIR}${MANDIR} &&					\
    (cd ${DESTDIR}${MANDIR}; chmod 644 ${PROGS}.1);				\
  fi
endef

proberoute: $(OBJS)
	${CC} ${CFLAGS} -D_$(OS) -o $@ $(filter-out %.dll,$^) $(LDFLAGS) $(LIBS)

ifeq (CYGWIN, $(OS))
  # must use C compile mode
objects = getmac.o getroute.o win_rawsock.o
$(objects): %.o: %.c getmac.h win_rawsock.h
	cc -Wall -g -c -o $@ $<

winsock.dll: $(objects)
	cc -shared -o $@ $^ -lws2_32

Packet.dll wpcap.dll: GetDllDirectory
	@export PATH=$$PATH:.; \
		DllDirectory=`GetDllDirectory`; \
		ls -1 $$DllDirectory | grep $@ | \
		while read line; do cp ''$${DllDirectory}''\\$$line .; done

GetDllDirectory: GetDllDirectory.c
	cc -g -Wall -mwindows -o GetDllDirectory GetDllDirectory.c
endif

%.o: %.cpp ProbeRoute.hpp config.h usage.h
	$(CC) $(CPPFLAGS) -c -o $@ $<

usage.h: usage.txt
	@echo 'P("proberoute  version $(VERSION) build on $(OS) at '`date`'");' >$@
	sed <$< -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/.*/P("&");/' | tr -d '\r' >>$@ 

install: $(PROGS) $(PROGS).1
	$(install-func)

man: doc/$(PROGS)_man.pdf

doc/$(PROGS)_man.pdf: $(PROGS).1
	@mkdir -p doc
	$(if $(filter AIX,$(OS)),\
	troff -man -Tpsc <$< | psc >doc/$(PROGS).ps,\
	groff -man -Tps <$< >doc/$(PROGS).ps)
	cd doc && ps2pdf $(PROGS).ps $(subst doc/,,$@)

BUILDDIR := build
.PHONY: clean_build
clean_build:
	@rm -rf ${BUILDDIR}/*

ifeq (CYGWIN, $(OS))
  # copy the DLL file to build folder
  build: $(PROGS) clean_build
	@[ -d ${BUILDDIR}/ ] || mkdir -p ${BUILDDIR}/
	@cygcheck ./$(PROGS) | sed '1d' | grep -e cygwin -e pcap -e packet | sed 's/\\/\\\\/g' | \
	while read f; do cp -p $$f ${BUILDDIR}/; done
	cp -p $(PROGS) ${BUILDDIR}/ && strip ${BUILDDIR}/$(PROGS)
endif

clean:
	rm -rf ${PROGS} *.exe *.o *.dll core *.BAK *~ usage.h ${BUILDDIR}
