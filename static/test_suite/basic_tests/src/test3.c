#include <stddef.h>
#define STDOUT 1
#define __NR_write 4

static size_t write_syscall(int fd, const void *buf, size_t size) {
    register int rax __asm__ ("rax") = 1;
    register int rdi __asm__ ("rdi") = fd;
    register const void *rsi __asm__ ("rsi") = buf;
    register size_t rdx __asm__ ("rdx") = size;
    __asm__ __volatile__ (
        "syscall"
        : "+r" (rax)
        : "r" (rdi), "r" (rsi), "r" (rdx)
        : "rcx", "r11", "memory"
    );
    return rax;
}

static void exit_syscall(int exit_status) {
    register int rax __asm__ ("rax") = 60;
    register int rdi __asm__ ("rdi") = exit_status;
    __asm__ __volatile__ (
        "syscall"
        : "+r" (rax)
        : "r" (rdi)
        : "rcx", "r11", "memory"
    );
}

static int add(int a, int b) {
    const char msg[] = "call add\n";
    write_syscall(STDOUT, msg, sizeof(msg));
}

static int subtract(int a, int b) {
    const char msg[] = "call subtract\n";
    write_syscall(STDOUT, msg, sizeof(msg));
}

int main() {

    int (*operationPtr)(int, int);
    operationPtr = &add;
    int result = operationPtr(5, 3);

    operationPtr = &subtract;
    result = operationPtr(5, 3);

    exit_syscall(0);
}
