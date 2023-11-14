#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <openssl/md5.h>

typedef unsigned char *(*MD5Function)(const unsigned char *, size_t, unsigned char *);

int main() {

    void *handle = dlopen("libcrypto.so", RTLD_LAZY);

    if (!handle) {
        fprintf(stderr, "Error: %s\n", dlerror());
        return 1;
    }

    MD5Function md5 = (MD5Function)dlsym(handle, "MD5");

    if (!md5) {
        fprintf(stderr, "Error: %s\n", dlerror());
        dlclose(handle);
        return 1;
    }

    const char *data = "Hello, World!";
    unsigned char hash[MD5_DIGEST_LENGTH];

    md5((const unsigned char *)data, strlen(data), hash);

    printf("MD5 Hash: ");
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    dlclose(handle);
    return 0;
}