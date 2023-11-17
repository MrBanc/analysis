#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef ssize_t (*WriteFunction)(int, const void*, size_t);

ssize_t writeHello(int fd, const void* buf, size_t count);
ssize_t writeWorld(int fd, const void* buf, size_t count);

int main() {
    WriteFunction writeFunctions[] = {writeHello, writeWorld};

    for (int i = 0; i < sizeof(writeFunctions) / sizeof(writeFunctions[0]); ++i) {
        ssize_t result = writeFunctions[i](STDOUT_FILENO, " - ", 3);

        if (result == -1) {
            perror("Write syscall failed");
            exit(EXIT_FAILURE);
        }
    }

    printf("\n");

    return 0;
}

ssize_t writeHello(int fd, const void* buf, size_t count) {
    return write(fd, "Hello", 5);
}

ssize_t writeWorld(int fd, const void* buf, size_t count) {
    return write(fd, "World", 5);
}