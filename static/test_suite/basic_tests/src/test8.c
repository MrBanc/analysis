#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <syscall.h>
#include <pcre.h>

typedef long (*SyscallFunction)();

typedef unsigned char *(*MD5Function)(const unsigned char *, size_t, unsigned char *);
typedef unsigned char *(*pcre_compile_t)(const unsigned char *, size_t, unsigned char *);

int main() {
    void *pcre_handle = dlopen("/usr/lib64/libpcre.so", RTLD_LAZY);
    if (!pcre_handle) {
        pcre_handle = dlopen("/lib/x86_64-linux-gnu/libpcre.so.3.13.3", RTLD_LAZY);
    }
    if (!pcre_handle) {
        fprintf(stderr, "Error loading PCRE library: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }
    printf("PCRE library loaded successfully.\n");

    void *crypto_handle = dlopen("libcrypto.so", RTLD_LAZY);
    if (!crypto_handle) {
        fprintf(stderr, "Error loading libcrypto library: %s\n", dlerror());
        dlclose(pcre_handle);
        exit(EXIT_FAILURE);
    }
    printf("libcrypto library loaded successfully.\n");

    MD5Function md5 = (MD5Function)dlsym(crypto_handle, "MD5");

    if (!md5) {
        fprintf(stderr, "Error: %s\n", dlerror());
        dlclose(pcre_handle);
        dlclose(crypto_handle);
        exit(EXIT_FAILURE);
    }

    const char *data = "Hello, World!";
    unsigned char hash[MD5_DIGEST_LENGTH];

    md5((const unsigned char *)data, strlen(data), hash);

    printf("MD5 Hash: ");
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    pcre_compile_t pcre_compile_func = (pcre_compile_t)dlsym(pcre_handle, "pcre_compile");
    if (!pcre_compile_func) {
        fprintf(stderr, "Error loading pcre_compile: %s\n", dlerror());
        dlclose(pcre_handle);
        dlclose(crypto_handle);
        exit(EXIT_FAILURE);
    }

    dlclose(pcre_handle);
    dlclose(crypto_handle);

    return syscall(SYS_exit,0);
}
