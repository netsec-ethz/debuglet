package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("Hello from Debuglet!")
	// The host passes guest arguments directly, without a program-name entry.
	for _, arg := range os.Args {
		fmt.Println(arg)
	}
}
