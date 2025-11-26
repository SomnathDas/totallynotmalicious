# --- Variables ---
CC = gcc
NASM = nasm
LD = ld

# Compiler Flags for C (Stager)
# -Wall: Enable warnings
# -g:    Add debug info (useful for gdb)
CFLAGS = -Wall -g

# Linker Flags for C (Stager)
# -lcapstone: Link against the Capstone disassembly engine
LIBS = -lcapstone

# --- Targets ---

.PHONY: all clean

all: stager payload

# 1. Compile the Stager
stager: stager.c
	$(CC) $(CFLAGS) stager.c -o stager $(LIBS)

# 2. Compile the Payload
payload: payload.o
	$(LD) payload.o -o payload

# Compile Assembly to Object file
payload.o: payload.asm
	$(NASM) -f elf64 payload.asm -o payload.o

# --- Clean ---
clean:
	rm -f stager payload payload.o