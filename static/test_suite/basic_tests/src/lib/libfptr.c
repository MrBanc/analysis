#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <syscall.h>

#include "libfptr2.h"

long customSyscall1() {
    return syscall(SYS_mkdir, "/tmp/remove_tmp", strlen("/tmp/remove_tmp"));
}

void customSyscallsWrapper() {
    long (*sys_fptr)();

    sys_fptr = customSyscall1;
    long result = sys_fptr();
    printf("Result of syscall 1: %ld\n", result);

    sys_fptr = customSyscall2;
    result = sys_fptr();
    printf("Result of syscall 2: %ld\n", result);
}
