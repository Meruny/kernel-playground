# Makefile

BPF_CLANG=clang
BPF_CFLAGS=-O2 -g -Wall -target bpf

all:
	$(BPF_CLANG) $(BPF_CFLAGS) -c xdp_whitelist_kern.c -o xdp_whitelist_kern.o

clean:
	rm -f *.o *.out
