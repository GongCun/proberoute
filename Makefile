CC = c++
override CFLAGS += -Wall -g
override CPPFLAGS += -Wall -g
override LIBS += -lpcap 

OBJS = main.o ProbeAddressInfo.o ProbeException.o ProbePcap.o ProbeSock.o

PROGS = proberoute

all: ${PROGS}


proberoute: $(OBJS) 
	${CC} ${CFLAGS} -o $@ $^ $(LIBS)

# No need, just for g++
#$(OBJS): export CPLUS_INCLUDE_PATH = /usr/include
#$(OBJS): export OBJC_INCLUDE_PATH = /usr/lib

%.o: %.cpp ProbeRoute.hpp config.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f ${PROGS} *.o core *.BAK *~
