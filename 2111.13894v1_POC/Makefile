# ------------------------------------------------------------
# Tools & flags
# ------------------------------------------------------------
AS      = nasm
ASFLAGS = -f elf64
LD      = ld
CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c11

# ------------------------------------------------------------
# Files
# ------------------------------------------------------------
ASM_SRC   = payload.asm
OBJ       = payload.o
PAYLOAD   = payload
MAIN_SRC  = stager.c
CONFIG_H  = config.h
EXEC      = stager

# ------------------------------------------------------------
# Default target
# ------------------------------------------------------------
.PHONY: all clean
all: $(EXEC)

# ------------------------------------------------------------
# 1. Assemble
# ------------------------------------------------------------
$(OBJ): $(ASM_SRC)
	$(AS) $(ASFLAGS) $< -o $@

# ------------------------------------------------------------
# 2. Link payload
# ------------------------------------------------------------
$(PAYLOAD): $(OBJ)
	$(LD) $< -o $@

# ------------------------------------------------------------
# 3. Generate config.h from .text instruction addresses
# ------------------------------------------------------------
$(CONFIG_H): $(PAYLOAD)
	@echo "Extracting instruction addresses from $(PAYLOAD)..."
	@rm -f $@ .addresses.txt

	@# Extract only lines with opcode (format: "  401000:	90 ...")
	@objdump -M intel -d $(PAYLOAD) | \
	  grep -E '^[[:space:]]*[0-9a-f]+:' | \
	  sed -E 's/^[[:space:]]*([0-9a-f]+):.*/0x\1/' | \
	  sort -u > .addresses.txt

	@count=$$(wc -l < .addresses.txt); \
	if [ $$count -eq 0 ]; then \
	  echo "ERROR: No instruction addresses found!" >&2; \
	  exit 1; \
	fi; \
	\
	{ \
	  echo "#ifndef CONFIG_H"; \
	  echo "#define CONFIG_H"; \
	  echo ""; \
	  echo "const long PAYLOAD_INSTRUCTION_OFFSETS[] = {"; \
	  sed 's/.*/  &,/' .addresses.txt | sed '$$s/,$$//'; \
	  echo "};"; \
	  echo "#define PAYLOAD_ADDRESS_COUNT $$count"; \
	  echo ""; \
	  echo "#endif /* CONFIG_H */"; \
	} > $@

	@rm -f .addresses.txt
	@echo "$(CONFIG_H) generated with $$count instruction addresses."

# ------------------------------------------------------------
# 4. Compile stager
# ------------------------------------------------------------
$(EXEC): $(MAIN_SRC) $(CONFIG_H)
	$(CC) $(CFLAGS) $< -o $@

# ------------------------------------------------------------
# Clean
# ------------------------------------------------------------
clean:
	rm -f $(OBJ) $(PAYLOAD) $(CONFIG_H) $(EXEC) .addresses.txt