CC = xlc++ -g
override CFLAGS += -qflag=i:i -qinfo=use
override CPPFLAGS += -qflag=i:i -qinfo=use -I/usr/include -D_AIX 
override LIBS += -L/usr/lib -lpcap 

OBJS = main.o ProbeAddressInfo.o ProbeException.o ProbePcap.o ProbeSock.o

PROGS = proberoute

all: ${PROGS}

proberoute: $(OBJS) 
	${CC} ${CFLAGS} -o $@ $^ $(LIBS)

# No need, just for g++
#$(OBJS): export CPLUS_INCLUDE_PATH = /usr/include
#$(OBJS): export OBJC_INCLUDE_PATH = /usr/lib

%.o: %.cpp ProbeRoute.hpp config.h usage.h
	$(CC) $(CPPFLAGS) -c -o $@ $<

usage.h: usage.txt
	sed <$< >$@ -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/.*/P("&");/'

clean:
	rm -f ${PROGS} *.o core *.BAK *~
