OS = $(shell uname -s |tr '[:lower:]' '[:upper:]')
CPPFLAGS += -D_$(OS)
VERSION = 1.0
BINDIR = /usr/local/bin

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

install: $(PROGS)
	@echo Copy to ${DESTDIR}$(BINDIR)
	[ -d ${DESTDIR}${BINDIR}/ ] || \
		(mkdir -p ${DESTDIR}${BINDIR}/; chmod 755 ${DESTDIR}${BINDIR}/)
	install -s -S -f ${DESTDIR}${BINDIR}/ -M 4755 -O root -G system ${PROGS}

clean:
	rm -f ${PROGS} *.o core *.BAK *~ config.*
