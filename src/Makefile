CC=gcc
CCFLAGS = -Wall -I.

HDIR = ../include
TDIR = ../bin
TARGET = packet-parser 

$(TARGET): main.o print.o read.o
	$(CC) $(CCFLAGS) -o $(TDIR)/$(TARGET) main.o print.o read.o

main.o: main.c $(HDIR)/read.h $(HDIR)/print.h $(HDIR)/ptype.h
	$(CC) $(CCFLAGS) -c main.c 

read.o: read.c $(HDIR)/read.h $(HDIR)/ptype.h 
	$(CC) $(CCFLAGS) -c read.c

print.o: print.c $(HDIR)/print.h $(HDIR)/ptype.h 
	$(CC) $(CCFLAGS) -c print.c

clean:
	rm -f *.o 