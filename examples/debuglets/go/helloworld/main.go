// Minimal "hello world" debuglet in Go.
//
// A debuglet is a WASI command module: write a normal func main() and build it
// with GOOS=wasip1 GOARCH=wasm. The executor runs _start and streams stdout back
// to the user, so fmt.Println is all we need.
//
// Build:
//
//	make wasm SAMPLE_DIR=examples/debuglets/go/helloworld
package main

import "fmt"

func main() {
	fmt.Println("Hello from Debuglet! (Go)")
}
