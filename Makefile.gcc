CC = c++
override CFLAGS += -Wall -g
override CPPFLAGS += -Wall -g
override LIBS += -lpcap -lpopt

OBJS = main.o ProbeAddressInfo.o ProbeException.o ProbePcap.o ProbeSock.o \
options_popt.o

PROGS = proberoute

all: ${PROGS}


proberoute: $(OBJS) 
	${CC} ${CFLAGS} -o $@ $^ $(LIBS)

# No need, just for g++
#$(OBJS): export CPLUS_INCLUDE_PATH = /usr/include
#$(OBJS): export OBJC_INCLUDE_PATH = /usr/lib

%.o: %.cpp ProbeRoute.hpp config.h usage.h
	$(CC) $(CFLAGS) -c -o $@ $<

usage.h: usage.txt
	sed <$< >$@ -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/.*/P("&");/'

clean:
	rm -f ${PROGS} *.o core *.BAK *~
