lib: libchariot_extractelf.a

all: lib

CFLAGS=-O2
# CFLAGS=-g -O0

libchariot_extractelf.a : chariot_extractelf.o
	rm -f $@
	ar cq $@ chariot_extractelf.o

chariot_extractelf.o: chariot_extractelf.c chariot_extractelf.h elf32.h
	gcc $(CFLAGS) -c $< -o $@

clean:
	rm -f libchariot_extractelf.a chariot_extractelf.o
