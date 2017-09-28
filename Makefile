OS = $(shell uname -s |tr '[:lower:]' '[:upper:]')
CPPFLAGS += -D_$(OS)

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
	sed <$< >$@ -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/.*/P("&");/'

clean:
	rm -f ${PROGS} *.o core *.BAK *~
