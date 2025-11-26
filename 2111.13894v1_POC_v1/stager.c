#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/memfd.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <elf.h>
#include <inttypes.h>
#include <capstone/capstone.h>

#define MAX_INSTRUCTIONS 1024

#ifndef __NR_memfd_create
#define __NR_memfd_create 319
#endif

/* TODO: Use a real data structure */
typedef struct {
    uint64_t addresses[MAX_INSTRUCTIONS];
    size_t count;
} AddressMap;

void add_to_map(AddressMap *map, uint64_t addr) {
    if (map->count < MAX_INSTRUCTIONS) {
        map->addresses[map->count++] = addr;
    } else {

        static int warned = 0;
        if (!warned) {
            fprintf(stderr, "[!] AddressMap is full (Limit: %d). Removing. \n", MAX_INSTRUCTIONS);
            warned = 1;
        }
    }
}

/* Helper Functions */
uintptr_t get_base_address(pid_t pid, const char *binary_name) {
    char filename[64], line[1024], pathname[512];
    FILE *fp;
    uintptr_t base_addr = 0;

    snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    fp = fopen(filename, "r");
    if (!fp) return 0;

    while (fgets(line, sizeof(line), fp)) {
        unsigned long start;
        // The first entry for the binary is the Image Base (ELF Header)
        if (strstr(line, binary_name)) {
            sscanf(line, "%lx-%*lx %*s %*x %*x:%*x %*u %s", &start, pathname);
            
            base_addr = start;
            break; 
        }
    }
    fclose(fp);
    return base_addr;
}

/* Parse ELF .text Section, Get the offsets using Capstone */
void parse_text_section(int fd, AddressMap *map) {
    if (fd < 0) {
        fprintf(stderr, "[-] Invalid fd provided\n");
        return;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        exit(1);
    }

    uint8_t *file_mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file_mem == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)file_mem;
    Elf64_Shdr *shdrs = (Elf64_Shdr *)(file_mem + ehdr->e_shoff);
    const char *shstrtab = (const char *)(file_mem + shdrs[ehdr->e_shstrndx].sh_offset);
    
    Elf64_Shdr *text_shdr = NULL;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *name = shstrtab + shdrs[i].sh_name;
        if (strcmp(name, ".text") == 0) {
            text_shdr = &shdrs[i];
            break;
        }
    }

    if (!text_shdr) {
        fprintf(stderr, "[-] No .text section found in SHM data\n");
        munmap(file_mem, st.st_size);
        return;
    }

    csh handle;
    cs_insn *insn;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        fprintf(stderr, "[-] Capstone init failed\n");
        munmap(file_mem, st.st_size);
        return;
    }

    size_t count = cs_disasm(handle, file_mem + text_shdr->sh_offset, text_shdr->sh_size, text_shdr->sh_offset, 0, &insn);

    map->count = 0;
    for (size_t i = 0; i < count; i++) {
        if (map->count < MAX_INSTRUCTIONS) {
            map->addresses[map->count] = insn[i].address;
            map->count++;
        }
    }

    cs_free(insn, count);
    cs_close(&handle);
    munmap(file_mem, st.st_size);
}

/* memfd_create for In-Memory execution */
int open_ramfs(void) {
    int fd = syscall(__NR_memfd_create, "payload", 1);
    if (fd < 0) {
    	perror("memfd_create"); 
    	exit(-1); 
    }
    return fd;
}

size_t write_data(void *ptr, size_t size, size_t nmemb, int shm_fd) {
    ssize_t bytes = write(shm_fd, ptr, size * nmemb);
    if (bytes < 0) {
        close(shm_fd); 
        exit(-1);
    }
    return nmemb;
}

/* Bomb the child with payload */
void run_target(int shm_fd) {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
        perror("PTRACE_TRACEME");
        exit(-1);
    }

    char *const argv[] = { "payload", NULL };
    char *const envp[] = { NULL };

    fexecve(shm_fd, argv, envp);
    perror("fexecve");
    exit(-1);
}

/* Hang the child in reverse */
void run_debugger(pid_t child_pid, AddressMap *map) {
    int wait_status;
    unsigned icounter = 0;

    wait(&wait_status);

    /* TODO: remove explicit "payload" */
    int base_addr = get_base_address(child_pid, "payload");

    printf("--- DEBUG (start)---\n");
    printf("[+] Base Address : %p\n", base_addr);

    for(size_t i = 0; i < map->count; i++) {
        printf("[+] <payload> addresses : %p\n", map->addresses[i]);
    }
    printf("--- DEBUG (end)---\n");

    for(size_t i = 0; i < map->count; i++) {
        map->addresses[i] += base_addr;
    }

    while(WIFSTOPPED(wait_status)) {
    	icounter++;
    	struct user_regs_struct regs;
    	ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    	unsigned instr = ptrace(PTRACE_PEEKTEXT, child_pid, regs.rip, 0);

        size_t target_index = (map->count - 1) - icounter;

    	regs.rip = map->addresses[target_index];
    	ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

    	if(ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0) < 0) {
    		return;
    	}

    	wait(&wait_status);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <payload>\n", argv[0]);
        return -1;
    }

    // Read payload (replace with some other logic like URL fetching)
    FILE *f = fopen(argv[1], "rb");
    if (!f) { 
    	perror("fopen"); 
    	return -1; 
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    void *buf = malloc(len);
    fread(buf, 1, len, f);
    fclose(f);

    // Load it in In-memory for execution
    int shm_fd = open_ramfs();
    write_data(buf, 1, len, shm_fd);
    free(buf);

    // Grab the .text offsets for Address Map
    AddressMap map;
    parse_text_section(shm_fd, &map);

    // Stager, reverse execution phase
    pid_t child = fork();

    int base_addr = get_base_address(child, "payload");

    if (child == 0) {
        run_target(shm_fd);
    } else if (child > 0) {
        run_debugger(child, &map);
    } else {
        perror("fork");
        return -1;
    }

    return 0;
}