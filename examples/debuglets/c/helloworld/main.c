// Minimal "hello world" debuglet in C.
//
// The refactored engine runs WASI command modules: define main() and build for
// the wasm32-wasi target. stdout is streamed back to the user, so printf() is
// all we need to report output.
//
// Build:
//   make wasm SAMPLE_DIR=examples/debuglets/c/helloworld

#include <stdio.h>

int main(void) {
    printf("Hello from Debuglet! (C)\n");
    return 0;
}
