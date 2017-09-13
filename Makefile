CC = c++
override CFLAGS += -Wall -g
override CPPFLAGS += -Wall -g
override LIBS += -lpcap 

OBJS = main.o ProbeAddressInfo.o ProbeException.o ProbePcap.o ProbeSock.o do_checksum.o

PROGS = proberoute

all: ${PROGS}

proberoute: $(OBJS) 
	${CC} ${CFLAGS} -o $@ $^ $(LIBS)

%.o: %.cpp ProbeRoute.hpp config.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f ${PROGS} *.o core *.BAK *~
