#include <stdio.h>

static int add(int a, int b) {
    return a + b;
}

static int subtract(int a, int b) {
    return a - b;
}

int main() {

    int (*operationPtr)(int, int);

    operationPtr = &add;

    int result = operationPtr(5, 3);
    printf("Result of add operation: %d\n", result);

    operationPtr = &subtract;

    result = operationPtr(5, 3);
    printf("Result of subtract operation: %d\n", result);

    return 0;
}
