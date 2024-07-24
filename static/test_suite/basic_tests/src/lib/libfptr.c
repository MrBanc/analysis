#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syscall.h>
#include <time.h>

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

void callSpecifiedFct(long (*sys_fptr)()) {
    long result = sys_fptr();
    printf("Result of syscall: %ld\n", result);
}

void callOneFctFromTable(long (*sys_fptr[])(), int len) {
    // randomly choose a function from the table
    srand(time(NULL));
    int i = rand() % len;

    long result = sys_fptr[i]();
    printf("Result of syscall: %ld\n", result);
}

void customSyscallsWrapperWithFctPtrTable() {
    long (*sys_fptr_table[2])();

    sys_fptr_table[0] = customSyscall1;
    sys_fptr_table[1] = customSyscall2;

    callSpecifiedFct(sys_fptr_table[0]);

    callOneFctFromTable(sys_fptr_table, 2);
}
