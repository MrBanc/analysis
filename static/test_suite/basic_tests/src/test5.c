#include <stdio.h>
#include <unistd.h>
#include <syscall.h>

typedef long (*SyscallFunction)();

long customSyscall1() {
    return syscall(SYS_write, STDOUT_FILENO, "Hello from customSyscall1\n", 26);
}

long customSyscall2() {
    return syscall(SYS_write, STDOUT_FILENO, "Hello from customSyscall2\n", 26);
}

int main() {

    SyscallFunction syscalls[] = {customSyscall1, customSyscall2};

    for (int i = 0; i < sizeof(syscalls) / sizeof(syscalls[0]); ++i) {
        long result = syscalls[i]();
        printf("Result of syscall %d: %ld\n", i + 1, result);
    }

    return 0;
}