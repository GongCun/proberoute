CC = xlc++ -g
override CFLAGS += -qflag=i:i -qinfo=use
##override CFLAGS += 
override CPPFLAGS += -qflag=i:i -qinfo=use -I/usr/include -D_AIX 
##override CPPFLAGS += -I/usr/include -D_AIX 
OBJS = main.o ProbeAddress.o ProbeException.o
LIBS = -L/usr/lib -lpcap 

PROGS = proberoute

all: ${PROGS}


proberoute: $(OBJS) 
	${CC} ${CFLAGS} -o $@ $^ $(LIBS)

# No need, just for g++
#$(OBJS): export CPLUS_INCLUDE_PATH = /usr/include
#$(OBJS): export OBJC_INCLUDE_PATH = /usr/lib
$(OBJS): %.o: %.cpp
	$(CC) -c $(CPPFLAGS) -o $@ $< 

clean:
	rm -f ${PROGS} *.o core *.BAK *~
