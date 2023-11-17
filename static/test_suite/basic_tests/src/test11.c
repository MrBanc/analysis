#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <syscall.h>

typedef long (*SyscallFunction)();

const static char* path = "/tmp/remove_tmp";

long customSyscall1() {
    return syscall(SYS_mkdir, path, strlen(path));
}

long customSyscall2() {
    return syscall(SYS_rmdir, path, strlen(path));
}

int main() {

    SyscallFunction syscalls[] = {customSyscall1, customSyscall2};

    
    for (int i = 0; i < sizeof(syscalls) / sizeof(syscalls[0]); ++i) {
        long result = syscalls[i]();
        printf("Result of syscall %d: %ld\n", i + 1, result);
    }

    return 0;
}