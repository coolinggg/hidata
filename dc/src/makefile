CC := gcc
#CFLAGS := -pipe -O -W -Wall -Wno-unused-parameter -Wunused-function -Wunused-variable -Wunused-value -g
CFLAGS := -g -W -Wall 
LINK := $(CC)


LIBS := -lpcap
OBJS := httpcap.o

httpdc: $(OBJS)
	$(LINK) -o httpdc $(OBJS) $(LIBPATH) $(LIBS)

httpcap.o: httpcap.c
	$(CC) -c $(CFLAGS) $(ALL_INCS) httpcap.c

clean:
	rm -rf $(OBJS) httpdc    


