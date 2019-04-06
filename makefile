lib: libchariot_extractelf.a

all: lib exe

CFLAGS=-O2
# CFLAGS=-g -O0

libchariot_extractelf.a : chariot_extractelf.o
	rm -f $@
	ar cq $@ chariot_extractelf.o

chariot_extractelf.o: chariot_extractelf.c chariot_extractelf.h elf32.h
	gcc $(CFLAGS) -c $< -o $@

exe: chariot_extractelf_meta_data.exe

chariot_extractelf_meta_data.exe: chariot_extractelf_meta_data.cpp libchariot_extractelf.a
	g++ -std=c++14 $(CFLAGS) $< -o $@ -L. -lchariot_extractelf

clean:
	rm -f libchariot_extractelf.a chariot_extractelf.o chariot_extractelf_meta_data.exe
