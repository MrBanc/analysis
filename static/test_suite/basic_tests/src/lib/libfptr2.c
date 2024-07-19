#include <syscall.h>
#include <string.h>
#include <unistd.h>
#include <syscall.h>

long customSyscall2() {
    return syscall(SYS_rmdir, "/tmp/remove_tmp", strlen("/tmp/remove_tmp"));
}
