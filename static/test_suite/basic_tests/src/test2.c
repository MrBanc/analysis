#include <stdio.h>

static int add(int a, int b) {
    printf("Result of add operation: %d\n", a + b);
}

static int subtract(int a, int b) {
    printf("Result of subtract operation: %d\n", a - b);
}

int main() {

    int (*operationPtr)(int, int);
    operationPtr = &add;
    int result = operationPtr(5, 3);

    operationPtr = &subtract;
    result = operationPtr(5, 3);

    return 0;
}
